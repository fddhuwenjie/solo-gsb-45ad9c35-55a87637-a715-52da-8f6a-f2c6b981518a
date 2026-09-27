"""Tests for POST /deployments/ocsp-precheck (offline OCSP staple check)."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from app.main import app

# Certificate validity is anchored at import time; OCSP response timestamps
# are anchored at real "now" because producedAt is stamped at signing time.
NOW = datetime.now(timezone.utc)

client = TestClient(app)


# ---------------------------------------------------------------------------
# PKI factory
# ---------------------------------------------------------------------------


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _dn(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_cn, issuer_cn, issuer_key, subject_key, *, ca,
          not_before=None, not_after=None, eku_ocsp_signing=False,
          serial=None):
    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn(subject_cn))
        .issuer_name(_dn(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(serial if serial is not None
                       else x509.random_serial_number())
        .not_valid_before(not_before or NOW - timedelta(days=30))
        .not_valid_after(not_after or NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                       critical=True)
    )
    if eku_ocsp_signing:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _root(cn="Root CA"):
    key = _key()
    return _cert(cn, cn, key, key, ca=True), key


def _leaf(issuer_cn, issuer_key, *, serial=None):
    key = _key()
    cert = _cert("api.example.com", issuer_cn, issuer_key, key, ca=False,
                 serial=serial)
    return cert, key


def _responder(issuer_cn, issuer_key, *, eku=True, not_before=None,
               not_after=None):
    key = _key()
    cert = _cert("OCSP Responder", issuer_cn, issuer_key, key, ca=False,
                 eku_ocsp_signing=eku, not_before=not_before,
                 not_after=not_after)
    return cert, key


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fp(cert) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def _response(issuer, issuer_key, leaf, *, signer_key=None, responder_cert=None,
              responder_encoding=ocsp.OCSPResponderEncoding.NAME,
              cert_status=ocsp.OCSPCertStatus.GOOD,
              this_update=None, next_update="default",
              revocation_time=None, revocation_reason=None,
              embedded=(), cert=None):
    """Build a DER OCSP response; producedAt is stamped at signing time."""
    if this_update is None:
        this_update = NOW - timedelta(hours=1)
    if next_update == "default":
        next_update = NOW + timedelta(days=7)
    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=cert if cert is not None else leaf,
        issuer=issuer,
        algorithm=hashes.SHA1(),
        cert_status=cert_status,
        this_update=this_update.replace(tzinfo=None),
        next_update=(next_update.replace(tzinfo=None)
                     if next_update is not None else None),
        revocation_time=(revocation_time.replace(tzinfo=None)
                         if revocation_time is not None else None),
        revocation_reason=revocation_reason,
    )
    builder = builder.responder_id(
        responder_encoding,
        responder_cert if responder_cert is not None else issuer,
    )
    if embedded:
        builder = builder.certificates(list(embedded))
    return builder.sign(signer_key or issuer_key, hashes.SHA256())


def der_b64(response) -> str:
    return base64.b64encode(
        response.public_bytes(serialization.Encoding.DER)
    ).decode()


def ocsp_precheck(bundle, leaf, response_b64, *, check_time=None, skew=0,
                  leaf_fingerprint=None):
    payload = {
        "pem_certificates": [pem(c) for c in bundle],
        "leaf_fingerprint": (leaf_fingerprint if leaf_fingerprint is not None
                             else fp(leaf)),
        "ocsp_response": response_b64,
        # Default: evaluated right after the response was signed, so
        # producedAt <= check_time holds on the happy path.
        "check_time": (check_time or datetime.now(timezone.utc)).isoformat(),
        "max_skew_seconds": skew,
    }
    return client.post("/deployments/ocsp-precheck", json=payload)


def good_setup(**resp_kwargs):
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    response = _response(root, root_key, leaf, **resp_kwargs)
    return root, leaf, der_b64(response)


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_eligible_issuer_signed_by_name():
    root, leaf, b64 = good_setup()
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is True
    assert body["reason"] == "ok"
    assert body["response_status"] == "successful"
    assert body["certificate_status"] == "good"
    assert body["responder_id_type"] == "name"
    assert body["signer_type"] == "issuer"
    assert body["issuer_fingerprint"] == fp(root)
    assert body["signer_fingerprint"] == fp(root)
    assert body["leaf_fingerprint"] == fp(leaf)
    assert body["produced_at"] is not None
    assert body["this_update"] is not None
    assert body["next_update"] is not None
    assert body["revocation_time"] is None
    assert body["revocation_reason"] is None


def test_eligible_issuer_signed_by_key_hash():
    root, leaf, b64 = good_setup(
        responder_encoding=ocsp.OCSPResponderEncoding.HASH
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is True
    assert body["responder_id_type"] == "key_hash"
    assert body["signer_type"] == "issuer"


def test_eligible_delegated_responder_by_key_hash():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    responder, responder_key = _responder("Root CA", root_key)
    response = _response(
        root, root_key, leaf,
        signer_key=responder_key,
        responder_cert=responder,
        responder_encoding=ocsp.OCSPResponderEncoding.HASH,
        embedded=[responder],
    )
    r = ocsp_precheck([leaf, root], leaf, der_b64(response))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is True
    assert body["responder_id_type"] == "key_hash"
    assert body["signer_type"] == "responder_certificate"
    assert body["signer_fingerprint"] == fp(responder)


def test_eligible_delegated_responder_by_name():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    responder, responder_key = _responder("Root CA", root_key)
    response = _response(
        root, root_key, leaf,
        signer_key=responder_key,
        responder_cert=responder,
        responder_encoding=ocsp.OCSPResponderEncoding.NAME,
        embedded=[responder],
    )
    r = ocsp_precheck([leaf, root], leaf, der_b64(response))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is True
    assert body["responder_id_type"] == "name"
    assert body["signer_type"] == "responder_certificate"


def test_issuer_embedded_in_response_still_counts_as_issuer():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    response = _response(root, root_key, leaf, embedded=[root])
    r = ocsp_precheck([leaf, root], leaf, der_b64(response))
    assert r.status_code == 200, r.text
    assert r.json()["signer_type"] == "issuer"


def test_base64_blob_tolerates_whitespace():
    root, leaf, b64 = good_setup()
    wrapped = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    r = ocsp_precheck([leaf, root], leaf, wrapped)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


# ---------------------------------------------------------------------------
# CertID / issuer checks
# ---------------------------------------------------------------------------


def test_issuer_not_found():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    b64 = der_b64(_response(root, root_key, leaf))
    r = ocsp_precheck([leaf], leaf, b64)  # bundle lacks the issuer
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "issuer_not_found"
    assert body["issuer_fingerprint"] is None


def test_cert_id_mismatch_serial():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key, serial=1111)
    other_leaf, _ = _leaf("Root CA", root_key, serial=2222)
    # Response speaks for the other leaf's serial number.
    b64 = der_b64(_response(root, root_key, leaf, cert=other_leaf))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "cert_id_mismatch"
    assert body["issuer_fingerprint"] is None


def test_cert_id_mismatch_issuer_hashes():
    root, root_key = _root()
    other_root, other_root_key = _root("Other Root CA")
    leaf, _ = _leaf("Root CA", root_key)
    # Same serial, but the CertID issuer hashes name the other CA.
    b64 = der_b64(_response(other_root, other_root_key, leaf))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "cert_id_mismatch"


# ---------------------------------------------------------------------------
# Signer selection
# ---------------------------------------------------------------------------


def test_responder_not_found():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    stranger, stranger_key = _responder("Root CA", root_key)
    # ResponderID names a certificate that is not embedded in the response.
    b64 = der_b64(_response(root, root_key, leaf,
                            signer_key=stranger_key,
                            responder_cert=stranger))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "responder_not_found"
    assert body["signer_type"] is None


def test_unauthorized_responder_missing_eku():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    responder, responder_key = _responder("Root CA", root_key, eku=False)
    b64 = der_b64(_response(root, root_key, leaf,
                            signer_key=responder_key,
                            responder_cert=responder,
                            embedded=[responder]))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "unauthorized_responder"


def test_unauthorized_responder_not_issued_by_issuer():
    root, root_key = _root()
    other_root, other_root_key = _root("Other Root CA")
    leaf, _ = _leaf("Root CA", root_key)
    # Responder cert is issued by a different CA, not by the leaf's issuer.
    responder, responder_key = _responder("Other Root CA", other_root_key)
    b64 = der_b64(_response(root, root_key, leaf,
                            signer_key=responder_key,
                            responder_cert=responder,
                            embedded=[responder]))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "unauthorized_responder"


def test_unauthorized_responder_expired_at_check_time():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    responder, responder_key = _responder(
        "Root CA", root_key,
        not_before=NOW - timedelta(days=30),
        not_after=NOW - timedelta(hours=1),
    )
    b64 = der_b64(_response(root, root_key, leaf,
                            signer_key=responder_key,
                            responder_cert=responder,
                            embedded=[responder]))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "unauthorized_responder"


def test_signature_invalid():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    response = _response(root, root_key, leaf)
    # Flip the last byte of the DER: with no embedded certs the signature
    # BIT STRING is the final element, so this corrupts the signature while
    # keeping the envelope parseable.
    der = bytearray(response.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0x01
    r = ocsp_precheck([leaf, root], leaf, base64.b64encode(bytes(der)).decode())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "signature_invalid"
    assert body["signer_type"] == "issuer"


# ---------------------------------------------------------------------------
# Certificate status
# ---------------------------------------------------------------------------


def test_certificate_revoked_carries_time_and_reason():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    revoked_at = NOW - timedelta(hours=2)
    b64 = der_b64(_response(
        root, root_key, leaf,
        cert_status=ocsp.OCSPCertStatus.REVOKED,
        revocation_time=revoked_at,
        revocation_reason=x509.ReasonFlags.key_compromise,
    ))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "certificate_revoked"
    assert body["certificate_status"] == "revoked"
    assert body["revocation_reason"] == "key_compromise"
    assert body["revocation_time"] is not None
    assert body["revocation_time"].startswith(
        revoked_at.replace(microsecond=0).isoformat()[:19]
    )


def test_certificate_revoked_without_reason():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    b64 = der_b64(_response(
        root, root_key, leaf,
        cert_status=ocsp.OCSPCertStatus.REVOKED,
        revocation_time=NOW - timedelta(hours=2),
    ))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reason"] == "certificate_revoked"
    assert body["revocation_reason"] is None
    assert body["revocation_time"] is not None


def test_certificate_unknown():
    root, leaf, b64 = good_setup(cert_status=ocsp.OCSPCertStatus.UNKNOWN)
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "certificate_unknown"
    assert body["certificate_status"] == "unknown"


def test_response_not_successful():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    response = ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.UNAUTHORIZED
    )
    r = ocsp_precheck([leaf, root], leaf, der_b64(response))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "response_not_successful"
    assert body["response_status"] == "unauthorized"
    assert body["certificate_status"] is None


def test_invalid_ocsp_response():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    for blob in ("!!!not-base64!!!",
                 base64.b64encode(b"garbage, not DER").decode()):
        r = ocsp_precheck([leaf, root], leaf, blob)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["eligible"] is False
        assert body["reason"] == "invalid_ocsp_response"
        assert body["response_status"] is None


# ---------------------------------------------------------------------------
# Freshness window
# ---------------------------------------------------------------------------


def test_produced_at_in_future():
    root, leaf, b64 = good_setup()
    # producedAt is stamped "now"; a check_time a day in the past rejects it.
    r = ocsp_precheck([leaf, root], leaf, b64,
                      check_time=NOW - timedelta(days=1))
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "produced_at_in_future"


def test_produced_at_within_skew():
    root, leaf, b64 = good_setup()
    # check_time slightly behind producedAt, covered by the skew allowance.
    r = ocsp_precheck([leaf, root], leaf, b64,
                      check_time=datetime.now(timezone.utc)
                      - timedelta(seconds=100),
                      skew=300)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_next_update_missing():
    root, leaf, b64 = good_setup(next_update=None)
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "next_update_missing"
    assert body["next_update"] is None


def test_response_not_yet_valid():
    root, leaf, b64 = good_setup(
        this_update=NOW + timedelta(hours=1),
        next_update=NOW + timedelta(days=7),
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "response_not_yet_valid"


def test_response_not_yet_valid_rescued_by_skew():
    root, leaf, b64 = good_setup(
        this_update=datetime.now(timezone.utc) + timedelta(seconds=100),
        next_update=NOW + timedelta(days=7),
    )
    r = ocsp_precheck([leaf, root], leaf, b64, skew=300)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_response_stale():
    root, leaf, b64 = good_setup(
        this_update=NOW - timedelta(days=10),
        next_update=NOW - timedelta(hours=1),
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "response_stale"


def test_response_stale_rescued_by_skew():
    root, leaf, b64 = good_setup(
        this_update=NOW - timedelta(days=10),
        next_update=datetime.now(timezone.utc) - timedelta(seconds=100),
    )
    r = ocsp_precheck([leaf, root], leaf, b64, skew=300)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_skew_boundary_is_inclusive():
    root, leaf, b64 = good_setup(
        this_update=NOW - timedelta(days=10),
        next_update=NOW,  # exactly check_time-ish; well within any skew
    )
    r = ocsp_precheck([leaf, root], leaf, b64, skew=300)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


# ---------------------------------------------------------------------------
# Request-level validation (422)
# ---------------------------------------------------------------------------


def test_invalid_fingerprint_format():
    root, leaf, b64 = good_setup()
    r = ocsp_precheck([leaf, root], leaf, b64, leaf_fingerprint="zz" * 32)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_fingerprint"
    assert detail["fingerprint_issues"][0]["referred_by"] == "leaf_fingerprint"
    # The OCSP route shares the normalize error shape (no identity_issues).
    assert "identity_issues" not in detail


def test_unknown_fingerprint():
    root, leaf, b64 = good_setup()
    r = ocsp_precheck([leaf, root], leaf, b64, leaf_fingerprint="0" * 64)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "unknown_fingerprint"


def test_invalid_pem():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    payload = {
        "pem_certificates": ["not a pem block"],
        "leaf_fingerprint": fp(leaf),
        "ocsp_response": "AAAA",
        "check_time": NOW.isoformat(),
        "max_skew_seconds": 0,
    }
    r = client.post("/deployments/ocsp-precheck", json=payload)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_pem"
    assert detail["pem_issues"][0]["index"] == 0


def test_skew_capped_at_300_seconds():
    root, leaf, b64 = good_setup()
    r = ocsp_precheck([leaf, root], leaf, b64, skew=301)
    assert r.status_code == 422


def test_naive_check_time_treated_as_utc():
    root, leaf, b64 = good_setup()
    payload = {
        "pem_certificates": [pem(leaf), pem(root)],
        "leaf_fingerprint": fp(leaf),
        "ocsp_response": b64,
        "check_time": datetime.now(timezone.utc)
        .replace(tzinfo=None)
        .isoformat(),
        "max_skew_seconds": 300,
    }
    r = client.post("/deployments/ocsp-precheck", json=payload)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_uppercase_fingerprint_accepted():
    root, leaf, b64 = good_setup()
    r = ocsp_precheck([leaf, root], leaf, b64,
                      leaf_fingerprint=fp(leaf).upper())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is True
    assert body["leaf_fingerprint"] == fp(leaf)  # normalized to lower-case
