"""FastAPI application exposing the rotation planning endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from .engine import (
    ReplayFailure,
    ScenarioValidationError,
    build_scenario,
    check_batch,
    eager_failure,
    initial_state,
    state_for_mask_applied,
)
from .models import (
    ChainCert,
    Failure,
    NormalizeErrorDetail,
    NormalizeRequest,
    NormalizeResult,
    OcspPrecheckRequest,
    OcspPrecheckResult,
    PlannedStage,
    PlanRequest,
    PlanSuccess,
    PrecheckErrorDetail,
    PrecheckRequest,
    PrecheckResult,
    ReconcileConflict,
    ReconcileRequest,
    ReconcileResult,
    RelationshipRef,
)
from .normalize import NormalizeError, normalize_scenario
from .ocsp import ocsp_precheck
from .precheck import precheck_identities
from .reconcile import reconcile


class _NormalizeErrorResponse(BaseModel):
    detail: NormalizeErrorDetail


class _PrecheckErrorResponse(BaseModel):
    detail: PrecheckErrorDetail

app = FastAPI(
    title="TLS Certificate Zero-Downtime Rotation Planner",
    version="1.0.0",
    description=(
        "Plan and verify zero-downtime TLS certificate rotations. After every "
        "stage, every required client→endpoint relationship must still have a "
        "valid trust path (a chain from the endpoint leaf to one of the "
        "client's trust anchors)."
    ),
)


@app.exception_handler(ScenarioValidationError)
async def _scenario_validation_handler(_request, exc: ScenarioValidationError):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.exception_handler(NormalizeError)
async def _normalize_error_handler(request, exc: NormalizeError):
    # Both /scenarios/normalize and /deployments/precheck raise NormalizeError
    # (shared PEM/fingerprint/chain diagnostics); only the pre-check carries
    # identity_issues, so shape the detail per route.
    if request.url.path.startswith("/deployments/precheck"):
        detail = PrecheckErrorDetail(
            error=exc.error,
            message=exc.message,
            pem_issues=exc.pem_issues,
            fingerprint_issues=exc.fingerprint_issues,
            chain_issues=exc.chain_issues,
            identity_issues=getattr(exc, "identity_issues", []),
        )
    else:
        detail = NormalizeErrorDetail(
            error=exc.error,
            message=exc.message,
            pem_issues=exc.pem_issues,
            fingerprint_issues=exc.fingerprint_issues,
            chain_issues=exc.chain_issues,
        )
    return JSONResponse(status_code=422, content={"detail": detail.model_dump()})


# ---------------------------------------------------------------------------
# /plans/verify request: a plan plus the same scenario payload
# ---------------------------------------------------------------------------


class VerifyStage(BaseModel):
    stage: int = Field(..., ge=1)
    action_ids: list[str] = Field(
        ...,
        description="Actions that execute at this absolute stage number. An "
        "empty list is a no-op stage: the trust state is carried over "
        "unchanged and still re-validated.",
    )

    @field_validator("action_ids")
    @classmethod
    def _unique(cls, v: list[str]) -> list[str]:
        if len(set(v)) != len(v):
            raise ValueError("action_ids within a stage must be unique")
        return v


class VerifyRequest(PlanRequest):
    plan: list[VerifyStage] = Field(
        default_factory=list,
        description="Stages numbered consecutively from 1. Empty action_ids "
        "mark a no-op stage (a legal gap when no action is eligible at that "
        "absolute stage); the whole plan may be empty only when the scenario "
        "defines no actions.",
    )


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _chain_dto(sc, cert_ids: list[str]) -> list[ChainCert]:
    return [
        ChainCert(
            cert_id=cid,
            subject=sc.certs[cid].subject,
            issuer=sc.certs[cid].issuer,
        )
        for cid in cert_ids
    ]


def _stages_dto(sc, batches: list[list[int]]) -> list[PlannedStage]:
    return [
        PlannedStage(
            stage=num,
            action_ids=[sc.action_ids[i] for i in batch],
        )
        for num, batch in enumerate(batches, start=1)
    ]


def _failure_dto(sc, rf: ReplayFailure, *, status: str) -> Failure:
    rel = sc.relationships[rf.relationship_index]
    return Failure(
        status=status,  # type: ignore[arg-type]
        stage=rf.stage,
        relationship=RelationshipRef(
            client_id=rel.client_id, endpoint_id=rel.endpoint_id
        ),
        blocking_action=(
            sc.action_ids[rf.blocking_action_index]
            if rf.blocking_action_index is not None
            else None
        ),
        reason=rf.reason,
        chain=_chain_dto(sc, rf.chain),
        trusted_anchors=rf.trusted_anchors,
        message=_failure_message(sc, rf),
    )


def _failure_message(sc, rf: ReplayFailure) -> str:
    rel = sc.relationships[rf.relationship_index]
    who = f"relationship {rel.client_id} -> {rel.endpoint_id}"
    if rf.stage == 0:
        prefix = "initial state already invalid"
    else:
        prefix = f"stage {rf.stage}"
    if rf.reason == "untrusted_root":
        broken = rf.chain[rf.failure_index]
        return (
            f"{prefix}: {who} loses its trust path; chain terminates at "
            f"'{broken}', which is not among the client's trust anchors "
            f"({', '.join(rf.trusted_anchors) or 'none'})"
        )
    if rf.reason == "issuer_mismatch":
        broken = rf.chain[rf.failure_index]
        nxt = rf.chain[rf.failure_index + 1]
        return (
            f"{prefix}: {who} chain breaks at '{broken}' -> '{nxt}': "
            f"issuer/subject mismatch"
        )
    if rf.reason == "action_not_allowed_at_stage":
        return (
            f"{prefix}: action is scheduled outside its allowed_stages; "
            f"{who} cannot be verified"
        )
    if rf.reason == "contradictory_actions_same_stage":
        return (
            f"{prefix}: an add_trust and a remove_trust on the same anchor are "
            f"scheduled together; {who} cannot be verified"
        )
    if rf.reason == "no_eligible_actions_at_stage":
        return (
            f"{prefix}: remaining actions are not allowed at this stage; "
            f"{who} cannot be maintained"
        )
    return f"{prefix}: {who} invalid ({rf.reason})"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post(
    "/scenarios/normalize",
    response_model=NormalizeResult,
    responses={422: {"model": _NormalizeErrorResponse}},
    summary="Normalize a shuffled PEM bundle into leaf-first verified chains",
)
def normalize_pem_bundle(req: NormalizeRequest) -> Any:
    """Parse a PEM bag, dedupe by DER fingerprint, establish issuance edges by
    real signature verification and reconstruct each endpoint's current/target
    leaf-first chain to a declared self-signed trust root.

    Returns 422 when a leaf has no verified path to a trust root or when
    cross-signing makes more than one such path possible; the detail lists the
    leaf, its cryptographic candidate issuers and the candidate paths.
    """
    return normalize_scenario(req)


@app.post(
    "/deployments/precheck",
    response_model=PrecheckResult,
    responses={422: {"model": _PrecheckErrorResponse}},
    summary="Pre-check target leaves' DNS/IP identities before planning",
)
def precheck_deployment(req: PrecheckRequest) -> Any:
    """Reconstruct each endpoint's target-leaf chain with the same signature
    verification as /scenarios/normalize, then certify the endpoint's claimed
    DNS/IP identities against the leaf's SANs (SAN-only; DNS normalized for
    case, trailing dot and IDNA A-labels; leftmost-label-only wildcards; IP
    exact) and against the name constraints accumulated along the
    intermediate CAs (excluded wins; permitted intersected).

    Results are sorted by endpoint_id with stable, machine-readable
    violations. Only ``eligible: true`` endpoints are safe to hand to
    ``/plans``; an ineligible endpoint's chain is still returned so the
    failure can be diagnosed without a second round trip.
    """
    return precheck_identities(req)


@app.post(
    "/deployments/ocsp-precheck",
    response_model=OcspPrecheckResult,
    responses={422: {"model": _NormalizeErrorResponse}},
    summary="Offline pre-check of a stapled OCSP response for one leaf",
)
def ocsp_precheck_deployment(req: OcspPrecheckRequest) -> Any:
    """Validate a stapled OCSP response offline against the PEM bundle.

    The leaf's issuer is established by signature verification inside the
    bundle (same machinery as /scenarios/normalize; no trust roots needed).
    The response CertID is checked against the leaf's serial number and the
    issuer's name/key hashes; the signer is selected by
    responderName/responderKeyHash and must be the issuer itself or a
    delegated responder certificate (directly issued by the issuer, valid at
    ``check_time``, carrying id-kp-OCSPSigning) whose signature is verified.
    The response must be successful with certificate status good, producedAt
    no later than ``check_time`` plus the skew allowance (at most 300s), and
    ``check_time`` must fall inside the thisUpdate/nextUpdate window widened
    by that skew; nextUpdate is required. Every failure returns 200 with
    ``eligible: false`` and a stable machine-readable reason (revoked
    verdicts also carry the revocation time and reason); malformed requests
    (bad fingerprint, unknown leaf, unparseable PEM) return 422.
    """
    return ocsp_precheck(req)


@app.post(
    "/plans",
    response_model=PlanSuccess,
    responses={409: {"model": Failure}},
    summary="Compute a minimum-stage zero-downtime rotation plan",
)
def create_plan(req: PlanRequest) -> Any:
    sc = build_scenario(req)
    from .engine import Solver

    solver = Solver(sc)

    if not solver.good[0]:
        rf = eager_failure(sc)
        response = _failure_dto(sc, rf, status="invalid")
        return JSONResponse(status_code=409, content=response.model_dump())

    min_stages = solver.finish(0, 1)
    if min_stages >= 10 ** 9:
        rf = eager_failure(sc)
        response = _failure_dto(sc, rf, status="infeasible")
        return JSONResponse(status_code=409, content=response.model_dump())

    batches = solver.solve()

    return PlanSuccess(stage_count=len(batches), stages=_stages_dto(sc, batches))


@app.post(
    "/plans/verify",
    summary="Replay an arbitrary plan stage by stage",
)
def verify_plan(req: VerifyRequest) -> Any:
    sc = build_scenario(req)

    # Structural validation of the submitted plan itself.
    known = set(sc.action_ids)
    seen: set[str] = set()
    expected_stage = 1
    for st in req.plan:
        if st.stage != expected_stage:
            raise ScenarioValidationError(
                f"plan: stages must be numbered consecutively from 1; "
                f"expected stage {expected_stage}, got {st.stage}"
            )
        expected_stage += 1
        for aid in st.action_ids:
            if aid not in known:
                raise ScenarioValidationError(
                    f"plan: unknown action_id '{aid}'"
                )
            if aid in seen:
                raise ScenarioValidationError(
                    f"plan: action '{aid}' appears more than once"
                )
            seen.add(aid)
    missing = sorted(known - seen)
    if missing:
        raise ScenarioValidationError(
            f"plan: every action must be scheduled exactly once; missing: "
            f"{', '.join(missing)}"
        )

    index = {aid: i for i, aid in enumerate(sc.action_ids)}
    state = initial_state(sc)

    # Stage 0: initial state must already hold.
    from .engine import first_broken_relationship

    broken = first_broken_relationship(sc, state)
    if broken is not None:
        ridx, pf = broken
        rf = ReplayFailure(
            stage=0,
            relationship_index=ridx,
            blocking_action_index=None,
            reason=pf.reason,
            chain=pf.chain,
            failure_index=pf.failure_index,
            trusted_anchors=pf.trusted_anchors,
        )
        response = _failure_dto(sc, rf, status="invalid")
        return JSONResponse(status_code=409, content=response.model_dump())

    batches: list[list[int]] = []
    for st in req.plan:
        batch_bits = 0
        batch_list: list[int] = []
        for aid in st.action_ids:
            i = index[aid]
            batch_bits |= 1 << i
            batch_list.append(i)
        # Empty batches are no-op stages: check_batch still re-validates every
        # relationship against the carried-over trust state afterwards, so a
        # legal gap is accepted and any breakage at it is still reported.
        rf = check_batch(sc, state, batch_bits, st.stage)
        if rf is not None:
            response = _failure_dto(sc, rf, status="invalid")
            return JSONResponse(status_code=409, content=response.model_dump())
        state = state_for_mask_applied(sc, state, batch_bits)
        batches.append(batch_list)

    return {
        "status": "valid",
        "stage_count": len(batches),
        "stages": _stages_dto(sc, batches),
    }


@app.post(
    "/plans/reconcile",
    response_model=ReconcileResult,
    responses={409: {"model": ReconcileConflict}},
    summary="Infer safe resumption points after an interrupted deployment",
)
def reconcile_plan(req: ReconcileRequest) -> Any:
    """Enumerate every plan-ordered progress state consistent with partial
    post-outage observations.

    Ended stages must have executed completely, the current stage may have
    executed any subset of its actions, later stages cannot have started, and
    states that already break a communication relationship or contradict an
    observation are discarded. Unobserved clients/anchors/endpoints stay
    unknown (never assumed absent). Returns all compatible progresses plus
    the actions safe to execute next in *every* one of them, or 409 with a
    stable conflict cut when no such state exists.
    """
    result = reconcile(req)
    if result.status == "conflict":
        return JSONResponse(status_code=409, content=result.model_dump())
    return result


@app.get("/health", summary="Liveness probe")
def health() -> dict[str, str]:
    return {"status": "ok"}
