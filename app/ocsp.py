"""Offline pre-check of a stapled OCSP response for one leaf certificate.

Given the same unordered PEM bag used by ``/scenarios/normalize`` (which must
contain the leaf and its issuer), the leaf's SHA-256 fingerprint, a
Base64-encoded DER OCSP response, a validation instant ``check_time`` and a
clock-skew tolerance of at most 300 seconds, this module decides whether the
stapled response may be served for that leaf at that instant.

The pipeline is a fixed precedence of checks; the first failure determines
the stable machine-readable ``reason`` of the 200 response:

1. ``invalid_ocsp_response`` — the blob is not Base64-decodable DER or fails
   to parse as an OCSP response.
2. ``response_not_successful`` — the response status is not ``successful``
   (such responses carry no single-response fields at all).
3. ``issuer_not_found`` — no certificate in the PEM bundle cryptographically
   signed the leaf (issuance is established by signature verification alone,
   reusing the normalizer's machinery; never by DN matching).
4. ``cert_id_mismatch`` — the response CertID matches no verified issuer:
   the serial number differs from the leaf's, or the issuer name/key hashes
   (recomputed with the response's own hash algorithm over the issuer's DER
   Name and subjectPublicKey bit string) do not line up.
5. ``responder_not_found`` — neither the issuer nor any certificate embedded
   in the response matches the responderID (selected by responderName, or by
   responderKeyHash = SHA-1 over the subjectPublicKey bit string).
6. ``unauthorized_responder`` — a certificate matches the responderID but is
   neither the issuer itself nor a delegated responder: directly signed by
   the issuer, valid at ``check_time`` and carrying the id-kp-OCSPSigning
   extended key usage.
7. ``signature_invalid`` — the response signature does not verify with the
   selected signer's public key. RSASSA-PSS responses are verified with the
   parameters parsed from the raw DER (explicit values and the RFC 4055
   defaults for hash, MGF1, salt length and trailerField); malformed or
   unsupported parameters land here too, never in an exception.
8. ``certificate_revoked`` / ``certificate_unknown`` — the (now authentic)
   response does not certify the leaf as good. A revoked verdict also
   surfaces ``revocation_time`` and ``revocation_reason``.
9. Freshness: ``produced_at_in_future`` (producedAt later than check_time +
   skew), ``next_update_missing`` (a nextUpdate freshness bound is required),
   ``response_not_yet_valid`` (check_time before thisUpdate − skew) and
   ``response_stale`` (check_time after nextUpdate + skew).

Only a response passing every check yields ``eligible: true``.
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import ocsp as x509_ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

from .models import (
    NormalizeFingerprintIssue,
    OcspPrecheckRequest,
    OcspPrecheckResult,
)
from .normalize import (
    FINGERPRINT_RE,
    NormalizeError,
    _RSASSA_PSS_OID,
    _build_issuer_edges,
    _load_pem_bundle,
    _validity_utc,
    _verify_signature,
    _verify_signed_data,
    cert_fingerprint,
)
from .precheck import _der_tlv


# ---------------------------------------------------------------------------
# Hashing helpers (RFC 6960 CertID / responderID)
# ---------------------------------------------------------------------------


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


_MISSING = object()


def _ocsp_time(response: x509_ocsp.OCSPResponse, attr: str) -> Optional[datetime]:
    """Timezone-aware OCSP timestamp, or None when the field is absent.

    cryptography >= 42 exposes ``*_utc`` variants; older versions return
    naive datetimes that are already expressed in UTC.
    """
    value = getattr(response, f"{attr}_utc", _MISSING)
    if value is _MISSING:
        value = getattr(response, attr)
    if value is None:
        return None
    return _as_utc(value)


def _subject_public_key_bits(cert: x509.Certificate) -> bytes:
    """Raw subjectPublicKey bit-string content of a certificate.

    This is the exact input of the KeyHash digests in RFC 6960 (CertID
    issuerKeyHash and the byKey responderID): the BIT STRING content without
    its tag, length and unused-bits count byte.
    """
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _tag, pos, _end, _c = _der_tlv(spki, 0)          # SEQUENCE
    _tag, _p, alg_end, _c = _der_tlv(spki, pos)      # algorithm SEQUENCE
    tag, start, end, _c = _der_tlv(spki, alg_end)    # BIT STRING
    if tag != 0x03 or end - start < 1:
        raise ValueError("malformed SubjectPublicKeyInfo")
    return spki[start + 1 : end]  # strip the unused-bits count byte


def _key_hash(cert: x509.Certificate, algorithm: str = "sha1") -> bytes:
    digest = hashlib.new(algorithm)
    digest.update(_subject_public_key_bits(cert))
    return digest.digest()


def _name_hash(cert: x509.Certificate, algorithm: str) -> bytes:
    digest = hashlib.new(algorithm)
    digest.update(cert.subject.public_bytes())
    return digest.digest()


def _cert_id_matches(
    response: x509_ocsp.OCSPResponse,
    leaf: x509.Certificate,
    issuer: x509.Certificate,
) -> bool:
    """Whether the response CertID speaks for ``leaf`` issued by ``issuer``."""
    try:
        algorithm = response.hash_algorithm.name
        name_hash = _name_hash(issuer, algorithm)
        key_hash = _key_hash(issuer, algorithm)
    except (TypeError, ValueError):
        return False  # hash algorithm unknown to hashlib: cannot match
    return (
        response.serial_number == leaf.serial_number
        and response.issuer_name_hash == name_hash
        and response.issuer_key_hash == key_hash
    )


# ---------------------------------------------------------------------------
# RSASSA-PSS signature parameters (RFC 4055 / RFC 8017)
#
# cryptography 44.0.3 raises UnsupportedAlgorithm for a PSS-signed response's
# ``signature_hash_algorithm`` and exposes no OCSP
# ``signature_algorithm_parameters``, so the RSASSA-PSS-params are parsed
# from the raw DER of the BasicOCSPResponse instead. The parser is
# deliberately strict — unknown hash/MGF OIDs, illegal TLV structure and
# duplicated, mis-ordered or out-of-range fields are all rejected — and every
# rejection is reported upstream as ``signature_invalid``; no exception leaks
# out of signature verification.
# ---------------------------------------------------------------------------

# DER value octets (tag/length stripped) of the relevant algorithm OIDs.
_RSASSA_PSS_OID_CONTENT = bytes.fromhex(
    "2a864886f70d01010a")  # 1.2.840.113549.1.1.10 (id-RSASSA-PSS)
_MGF1_OID_CONTENT = bytes.fromhex(
    "2a864886f70d010108")  # 1.2.840.113549.1.1.8 (id-mgf1)
_OCSP_BASIC_OID_CONTENT = bytes.fromhex(
    "2b0601050507300101")  # 1.3.6.1.5.5.7.48.1.1 (id-pkix-ocsp-basic)
_HASH_OID_CONTENT = {
    bytes.fromhex("2b0e03021a"): hashes.SHA1,        # 1.3.14.3.2.26
    bytes.fromhex("608648016503040204"): hashes.SHA224,  # 2.16.840.1.101.3.4.2.4
    bytes.fromhex("608648016503040201"): hashes.SHA256,  # 2.16.840.1.101.3.4.2.1
    bytes.fromhex("608648016503040202"): hashes.SHA384,  # 2.16.840.1.101.3.4.2.2
    bytes.fromhex("608648016503040203"): hashes.SHA512,  # 2.16.840.1.101.3.4.2.3
}

# RFC 4055 defaults for omitted RSASSA-PSS-params fields.
_PSS_DEFAULT_HASH = hashes.SHA1
_PSS_DEFAULT_SALT_LENGTH = 20
_PSS_TRAILER_FIELD_BC = 1


class _PssParamsError(ValueError):
    """Malformed or unsupported RSASSA-PSS-params (maps to signature_invalid)."""


def _der_read(buf: bytes, off: int, limit: int) -> tuple[int, int, int]:
    """Read one DER TLV from ``buf[off:limit]``.

    Returns ``(tag, content_start, content_end)``. Raises _PssParamsError on
    any structural violation: truncated header, indefinite or non-minimal
    length, or content overrunning the enclosing value.
    """
    if off < 0 or limit > len(buf) or off + 2 > limit:
        raise _PssParamsError("truncated TLV header")
    tag = buf[off]
    pos = off + 1
    length = buf[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > limit:
            raise _PssParamsError("illegal TLV length")
        if buf[pos] == 0:
            raise _PssParamsError("non-minimal TLV length")
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
        if length < 0x80:
            raise _PssParamsError("non-minimal TLV length")
    if pos + length > limit:
        raise _PssParamsError("TLV content overruns its enclosing value")
    return tag, pos, pos + length


def _basic_response_signature_algorithm(der: bytes) -> bytes:
    """Raw TLV bytes of the BasicOCSPResponse ``signatureAlgorithm`` field.

    Walks OCSPResponse -> [0] responseBytes -> BasicOCSPResponse in the raw
    DER; the parsed object model does not expose the parameters.
    """
    tag, c0, e0 = _der_read(der, 0, len(der))          # OCSPResponse SEQUENCE
    if tag != 0x30 or e0 != len(der):
        raise _PssParamsError("OCSPResponse is not one outer SEQUENCE")
    tag, _c, e1 = _der_read(der, c0, e0)               # responseStatus
    if tag != 0x0A:
        raise _PssParamsError("responseStatus is not an ENUMERATED")
    tag, c2, e2 = _der_read(der, e1, e0)               # [0] responseBytes
    if tag != 0xA0:
        raise _PssParamsError("responseBytes wrapper missing")
    tag, c3, e3 = _der_read(der, c2, e2)               # ResponseBytes SEQUENCE
    if tag != 0x30:
        raise _PssParamsError("ResponseBytes is not a SEQUENCE")
    tag, c4, e4 = _der_read(der, c3, e3)               # responseType OID
    if tag != 0x06 or der[c4:e4] != _OCSP_BASIC_OID_CONTENT:
        raise _PssParamsError("responseType is not id-pkix-ocsp-basic")
    tag, c5, e5 = _der_read(der, e4, e3)               # response OCTET STRING
    if tag != 0x04:
        raise _PssParamsError("response is not an OCTET STRING")
    tag, c6, e6 = _der_read(der, c5, e5)               # BasicOCSPResponse
    if tag != 0x30 or e6 != e5:
        raise _PssParamsError("BasicOCSPResponse is not a single SEQUENCE")
    tag, _c, e7 = _der_read(der, c6, e6)               # tbsResponseData
    if tag != 0x30:
        raise _PssParamsError("tbsResponseData is not a SEQUENCE")
    tag, _c, e8 = _der_read(der, e7, e6)               # signatureAlgorithm
    if tag != 0x30:
        raise _PssParamsError("signatureAlgorithm is not a SEQUENCE")
    return der[e7:e8]


def _pss_hash_algorithm(buf: bytes, start: int, end: int):
    """Hash class named by the HashAlgorithm in ``buf[start:end]``.

    The field must hold exactly one AlgorithmIdentifier SEQUENCE whose
    parameters are absent or NULL (the only forms RFC 4055/5754 define).
    """
    tag, c0, e0 = _der_read(buf, start, end)
    if tag != 0x30 or e0 != end:
        raise _PssParamsError("hashAlgorithm is not a single SEQUENCE")
    tag, c1, e1 = _der_read(buf, c0, e0)               # algorithm OID
    if tag != 0x06:
        raise _PssParamsError("hashAlgorithm carries no OID")
    hash_cls = _HASH_OID_CONTENT.get(buf[c1:e1])
    if hash_cls is None:
        raise _PssParamsError("unsupported hash algorithm OID")
    if e1 < e0:
        tag, c2, e2 = _der_read(buf, e1, e0)           # optional parameters
        if tag != 0x05 or c2 != e2 or e2 != e0:
            raise _PssParamsError(
                "hashAlgorithm parameters must be NULL or absent")
    return hash_cls


def _pss_mask_gen_algorithm(buf: bytes, start: int, end: int):
    """MGF1 hash class named by the MaskGenAlgorithm in ``buf[start:end]``.

    Only id-mgf1 is defined for RSASSA-PSS; its parameters (the hash the MGF
    is keyed with) are mandatory.
    """
    tag, c0, e0 = _der_read(buf, start, end)
    if tag != 0x30 or e0 != end:
        raise _PssParamsError("maskGenAlgorithm is not a single SEQUENCE")
    tag, c1, e1 = _der_read(buf, c0, e0)               # algorithm OID
    if tag != 0x06 or buf[c1:e1] != _MGF1_OID_CONTENT:
        raise _PssParamsError("unsupported mask generation function OID")
    if e1 >= e0:
        raise _PssParamsError("id-mgf1 requires its hash algorithm parameters")
    return _pss_hash_algorithm(buf, e1, e0)


def _pss_params_integer(buf: bytes, start: int, end: int, name: str) -> int:
    """Non-negative INTEGER wrapped in the params field ``buf[start:end]``."""
    tag, c0, e0 = _der_read(buf, start, end)
    if tag != 0x02 or e0 != end:
        raise _PssParamsError(f"{name} is not a single INTEGER")
    if c0 == e0:
        raise _PssParamsError(f"{name} INTEGER is empty")
    body = buf[c0:e0]
    if body[0] & 0x80:
        raise _PssParamsError(f"{name} must not be negative")
    if len(body) > 1 and body[0] == 0 and not body[1] & 0x80:
        raise _PssParamsError(f"{name} INTEGER is not minimally encoded")
    return int.from_bytes(body, "big")


def _parse_pss_params(content: Optional[bytes]):
    """RSASSA-PSS-params content octets -> (hash, MGF1 hash, salt length).

    ``content`` is None when the AlgorithmIdentifier omits the parameters
    element altogether. Omitted fields take their RFC 4055 defaults
    (SHA-1, MGF1-with-SHA-1, salt length 20, trailerFieldBC); the fields that
    are present must appear at most once, in their defined order.
    """
    hash_cls = _PSS_DEFAULT_HASH
    mgf_hash_cls = _PSS_DEFAULT_HASH
    salt_length = _PSS_DEFAULT_SALT_LENGTH
    if content is None:
        return hash_cls, mgf_hash_cls, salt_length
    pos = 0
    previous = -1
    while pos < len(content):
        tag, c0, e0 = _der_read(content, pos, len(content))
        if tag not in (0xA0, 0xA1, 0xA2, 0xA3):
            raise _PssParamsError("unknown RSASSA-PSS-params field")
        field = tag - 0xA0
        if field <= previous:
            raise _PssParamsError(
                "duplicated or mis-ordered RSASSA-PSS-params field")
        previous = field
        if field == 0:
            hash_cls = _pss_hash_algorithm(content, c0, e0)
        elif field == 1:
            mgf_hash_cls = _pss_mask_gen_algorithm(content, c0, e0)
        elif field == 2:
            salt_length = _pss_params_integer(content, c0, e0, "saltLength")
        else:
            trailer = _pss_params_integer(content, c0, e0, "trailerField")
            if trailer != _PSS_TRAILER_FIELD_BC:
                raise _PssParamsError(
                    "trailerField must be 1 (trailerFieldBC)")
        pos = e0
    return hash_cls, mgf_hash_cls, salt_length


def _parse_pss_signature_algorithm(sig_alg: bytes):
    """(hash, MGF1 hash, salt length) from a signatureAlgorithm TLV."""
    _tag, c0, e0 = _der_read(sig_alg, 0, len(sig_alg))
    tag, c1, e1 = _der_read(sig_alg, c0, e0)           # algorithm OID
    if tag != 0x06 or sig_alg[c1:e1] != _RSASSA_PSS_OID_CONTENT:
        raise _PssParamsError("signatureAlgorithm is not id-RSASSA-PSS")
    if e1 == e0:
        params_content = None  # parameters absent: RFC 4055 defaults
    else:
        tag, c2, e2 = _der_read(sig_alg, e1, e0)       # parameters
        if tag != 0x30 or e2 != e0:
            raise _PssParamsError(
                "RSASSA-PSS-params are not a single SEQUENCE")
        params_content = sig_alg[c2:e2]
    return _parse_pss_params(params_content)


def _pss_signature_parameters(
    der: bytes,
) -> Optional[tuple[hashes.HashAlgorithm, padding.PSS]]:
    """Hash algorithm and PSS padding of a PSS-signed OCSP response.

    Parsed from the raw DER because cryptography 44.0.3 cannot surface them
    for OCSP responses. Returns None when the parameters are malformed or
    unsupported; the caller reports that as ``signature_invalid``.
    """
    try:
        sig_alg = _basic_response_signature_algorithm(der)
        hash_cls, mgf_hash_cls, salt_length = _parse_pss_signature_algorithm(
            sig_alg)
    except _PssParamsError:
        return None
    hash_algorithm = hash_cls()
    return hash_algorithm, padding.PSS(
        mgf=padding.MGF1(mgf_hash_cls()),
        salt_length=salt_length,
    )


# ---------------------------------------------------------------------------
# Signer authorization
# ---------------------------------------------------------------------------


def _is_delegated_responder(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    check_time: datetime,
) -> bool:
    """Whether ``cert`` may sign OCSP responses on ``issuer``'s behalf.

    Requires a verifiable direct issuance by ``issuer``, validity at
    ``check_time`` and the id-kp-OCSPSigning extended key usage.
    """
    if not _verify_signature(cert, issuer):
        return False
    if not (
        _validity_utc(cert, "not_valid_before")
        <= check_time
        <= _validity_utc(cert, "not_valid_after")
    ):
        return False
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return False
    return ExtendedKeyUsageOID.OCSP_SIGNING in eku.value


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def ocsp_precheck(req: OcspPrecheckRequest) -> OcspPrecheckResult:
    # -- request-level validation (422, same shape as /scenarios/normalize) --
    leaf_fp = req.leaf_fingerprint.strip().lower()
    if not FINGERPRINT_RE.match(leaf_fp):
        raise NormalizeError(
            "invalid_fingerprint",
            "leaf_fingerprint is not a 64-character hex SHA-256 value",
            fingerprint_issues=[
                NormalizeFingerprintIssue(
                    fingerprint=req.leaf_fingerprint,
                    referred_by="leaf_fingerprint",
                )
            ],
        )

    certs, pem_issues = _load_pem_bundle(req.pem_certificates)
    if pem_issues:
        raise NormalizeError(
            "invalid_pem",
            "one or more PEM list elements could not be parsed",
            pem_issues=pem_issues,
        )

    if leaf_fp not in certs:
        raise NormalizeError(
            "unknown_fingerprint",
            "leaf_fingerprint does not match any certificate in the PEM "
            "bundle",
            fingerprint_issues=[
                NormalizeFingerprintIssue(
                    fingerprint=leaf_fp, referred_by="leaf_fingerprint"
                )
            ],
        )

    leaf = certs[leaf_fp]
    check_time = req.check_time  # normalized to UTC by the request model
    skew = timedelta(seconds=req.max_skew_seconds)

    info: dict[str, Any] = {
        "issuer_fingerprint": None,
        "response_status": None,
        "certificate_status": None,
        "responder_id_type": None,
        "signer_type": None,
        "signer_fingerprint": None,
        "produced_at": None,
        "this_update": None,
        "next_update": None,
        "revocation_time": None,
        "revocation_reason": None,
    }

    def finish(reason: str, message: str, *, eligible: bool = False):
        return OcspPrecheckResult(
            leaf_fingerprint=leaf_fp,
            eligible=eligible,
            reason=reason,  # type: ignore[arg-type]
            message=message,
            **info,
        )

    # -- 1. decode and parse the stapled response -----------------------------
    try:
        der = base64.b64decode(
            "".join(req.ocsp_response.split()), validate=True
        )
        response = x509_ocsp.load_der_ocsp_response(der)
    except ValueError as exc:
        return finish(
            "invalid_ocsp_response",
            f"ocsp_response is not a parseable Base64-encoded DER OCSP "
            f"response: {exc}",
        )

    # -- 2. the response must be successful ------------------------------------
    info["response_status"] = response.response_status.name.lower()
    if response.response_status is not x509_ocsp.OCSPResponseStatus.SUCCESSFUL:
        return finish(
            "response_not_successful",
            f"OCSP response status is {info['response_status']}, not "
            f"successful; it carries no certificate status to evaluate",
        )

    # Single-response fields exist only for successful responses.
    info["produced_at"] = _ocsp_time(response, "produced_at")
    info["this_update"] = _ocsp_time(response, "this_update")
    info["next_update"] = _ocsp_time(response, "next_update")
    info["certificate_status"] = response.certificate_status.name.lower()
    if response.certificate_status is x509_ocsp.OCSPCertStatus.REVOKED:
        info["revocation_time"] = _ocsp_time(response, "revocation_time")
        try:
            reason_flag = response.revocation_reason
        except ValueError:
            reason_flag = None  # unrecognised reason code: report as absent
        if reason_flag is not None:
            info["revocation_reason"] = reason_flag.name

    # -- 3./4. verified issuer + CertID ----------------------------------------
    edges = _build_issuer_edges(certs)
    issuer_fps = sorted(edges.get(leaf_fp, []))
    if not issuer_fps:
        return finish(
            "issuer_not_found",
            "no certificate in the PEM bundle cryptographically signed the "
            "leaf; the issuer is required to validate the CertID and to "
            "authorize the signer",
        )
    issuer_fp = next(
        (cand for cand in issuer_fps
         if _cert_id_matches(response, leaf, certs[cand])),
        None,
    )
    if issuer_fp is None:
        return finish(
            "cert_id_mismatch",
            "the response CertID matches no verified issuer of the leaf: "
            "the serial number differs from the leaf's, or the issuer "
            "name/key hashes do not line up",
        )
    issuer = certs[issuer_fp]
    info["issuer_fingerprint"] = issuer_fp

    # -- 5./6. signer selection by responderID ----------------------------------
    responder_name = response.responder_name
    responder_key_hash = response.responder_key_hash

    def matches_responder_id(cert: x509.Certificate) -> bool:
        if responder_name is not None:
            return cert.subject.public_bytes() == responder_name.public_bytes()
        try:
            return _key_hash(cert) == responder_key_hash
        except ValueError:
            return False

    if responder_name is not None:
        info["responder_id_type"] = "name"
    elif responder_key_hash is not None:
        info["responder_id_type"] = "key_hash"
    else:
        return finish(
            "invalid_ocsp_response",
            "the response carries no responderID (neither byName nor byKey)",
        )

    candidates = [issuer, *response.certificates]
    matching = [c for c in candidates if matches_responder_id(c)]
    if not matching:
        return finish(
            "responder_not_found",
            "neither the issuer nor any certificate embedded in the "
            "response matches the responderID",
        )

    issuer_der = issuer.public_bytes(serialization.Encoding.DER)
    signer: Optional[x509.Certificate] = None
    signer_type: Optional[str] = None
    for cand in matching:
        if cand.public_bytes(serialization.Encoding.DER) == issuer_der:
            signer, signer_type = cand, "issuer"
            break
    if signer is None:
        for cand in matching:
            if _is_delegated_responder(cand, issuer, check_time):
                signer, signer_type = cand, "responder_certificate"
                break
    if signer is None:
        return finish(
            "unauthorized_responder",
            "the responder is neither the issuer itself nor a responder "
            "certificate directly issued by it, valid at check_time and "
            "carrying the id-kp-OCSPSigning extended key usage",
        )
    info["signer_type"] = signer_type
    info["signer_fingerprint"] = cert_fingerprint(signer)

    # -- 7. the response signature must verify ----------------------------------
    signature_oid = response.signature_algorithm_oid.dotted_string
    if signature_oid == _RSASSA_PSS_OID:
        # cryptography 44.0.3 raises UnsupportedAlgorithm for a PSS-signed
        # response's signature_hash_algorithm and exposes no parameters, so
        # the RSASSA-PSS-params are parsed from the raw DER (RFC 4055
        # defaults included). Malformed or unsupported parameters mean the
        # signature cannot be verified: report signature_invalid.
        pss_parameters = _pss_signature_parameters(der)
        if pss_parameters is None:
            return finish(
                "signature_invalid",
                "the response's RSASSA-PSS signature parameters are "
                "malformed or use an unsupported hash/MGF algorithm",
            )
        hash_algorithm, signature_parameters = pss_parameters
    else:
        try:
            hash_algorithm = response.signature_hash_algorithm
        except UnsupportedAlgorithm:
            return finish(
                "signature_invalid",
                f"the response's signature algorithm (OID {signature_oid}) "
                f"is not supported",
            )
        signature_parameters = getattr(
            response, "signature_algorithm_parameters", None
        )
    if not _verify_signed_data(
        signer.public_key(),
        response.signature,
        response.tbs_response_bytes,
        hash_algorithm,
        signature_oid,
        signature_parameters,
    ):
        return finish(
            "signature_invalid",
            "the response signature does not verify with the selected "
            "signer's public key",
        )

    # -- 8. the leaf must be certified as good -----------------------------------
    if response.certificate_status is x509_ocsp.OCSPCertStatus.REVOKED:
        detail = ""
        if info["revocation_time"] is not None:
            detail += f" at {info['revocation_time'].isoformat()}"
        if info["revocation_reason"] is not None:
            detail += f" (reason: {info['revocation_reason']})"
        return finish(
            "certificate_revoked",
            f"the leaf is revoked{detail}",
        )
    if response.certificate_status is x509_ocsp.OCSPCertStatus.UNKNOWN:
        return finish(
            "certificate_unknown",
            "the responder does not certify the leaf's status (unknown)",
        )

    # -- 9. freshness ------------------------------------------------------------
    produced_at = info["produced_at"]
    if produced_at > check_time + skew:
        return finish(
            "produced_at_in_future",
            f"producedAt {produced_at.isoformat()} is later than check_time "
            f"{check_time.isoformat()} plus the {req.max_skew_seconds}s "
            f"skew allowance",
        )
    if info["next_update"] is None:
        return finish(
            "next_update_missing",
            "the response carries no nextUpdate; a freshness bound is "
            "required for a stapled response to be pre-checkable",
        )
    if check_time < info["this_update"] - skew:
        return finish(
            "response_not_yet_valid",
            f"check_time {check_time.isoformat()} is earlier than "
            f"thisUpdate {info['this_update'].isoformat()} minus the "
            f"{req.max_skew_seconds}s skew allowance",
        )
    if check_time > info["next_update"] + skew:
        return finish(
            "response_stale",
            f"check_time {check_time.isoformat()} is later than nextUpdate "
            f"{info['next_update'].isoformat()} plus the "
            f"{req.max_skew_seconds}s skew allowance",
        )

    return finish(
        "ok",
        "the stapled response is authentic, timely and certifies the leaf "
        "as good at check_time",
        eligible=True,
    )
