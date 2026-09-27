"""Tests for POST /deployments/ocsp-precheck (offline OCSP staple check)."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from app.main import app
from app.ocsp import _pss_signature_parameters

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


# ---------------------------------------------------------------------------
# RSASSA-PSS signed responses
#
# cryptography 44.0.3 raises UnsupportedAlgorithm for a PSS-signed response's
# signature_hash_algorithm and its OCSPResponseBuilder cannot produce one, so
# the responses below are assembled field by field from raw DER. The precheck
# must parse the RSASSA-PSS-params itself (explicit values and the RFC 4055
# defaults) and answer with a stable machine-readable reason — never an
# unhandled exception.
# ---------------------------------------------------------------------------


def _tlv(tag, content):
    if len(content) < 0x80:
        length = bytes([len(content)])
    else:
        body = len(content).to_bytes((len(content).bit_length() + 7) // 8,
                                     "big")
        length = bytes([0x80 | len(body)]) + body
    return bytes([tag]) + length + content


def _seq(*items):
    return _tlv(0x30, b"".join(items))


def _der_oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        out += bytes(reversed(chunk))
    return _tlv(0x06, out)


def _der_int(value):
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return _tlv(0x02, body)


def _explicit(number, *content):
    return _tlv(0xA0 + number, b"".join(content))


_NULL = b"\x05\x00"
_GENTIME = "%Y%m%d%H%M%SZ"

_PSS_OID = "1.2.840.113549.1.1.10"
_MGF1_OID = "1.2.840.113549.1.1.8"
_OCSP_BASIC_OID = "1.3.6.1.5.5.7.48.1.1"
_PSS_HASH_OIDS = {
    "sha1": "1.3.14.3.2.26",
    "sha224": "2.16.840.1.101.3.4.2.4",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
}
_PSS_HASHES = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


def _hash_alg_id(name):
    return _seq(_der_oid(_PSS_HASH_OIDS[name]), _NULL)


def _mgf1_alg_id(name):
    return _seq(_der_oid(_MGF1_OID), _hash_alg_id(name))


def _pss_params(hash_name, mgf_hash_name, salt_length, *, trailer=None):
    fields = [
        _explicit(0, _hash_alg_id(hash_name)),
        _explicit(1, _mgf1_alg_id(mgf_hash_name)),
        _explicit(2, _der_int(salt_length)),
    ]
    if trailer is not None:
        fields.append(_explicit(3, _der_int(trailer)))
    return _seq(*fields)


def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _rsa_root(cn="PSS Root CA"):
    key = _rsa_key()
    return _cert(cn, cn, key, key, ca=True), key


def _rsa_leaf(issuer_cn, issuer_key):
    key = _rsa_key()
    return _cert("api.example.com", issuer_cn, issuer_key, key, ca=False), key


def _rsa_responder(issuer_cn, issuer_key):
    key = _rsa_key()
    cert = _cert("OCSP Responder", issuer_cn, issuer_key, key, ca=False,
                 eku_ocsp_signing=True)
    return cert, key


def _spk_bits(cert):
    """subjectPublicKey bit-string content (CertID/responderID hash input)."""
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    def read(buf, off):
        pos = off + 1
        length = buf[pos]
        pos += 1
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(buf[pos:pos + n], "big")
            pos += n
        return pos, pos + length

    start, _ = read(spki, 0)        # SEQUENCE
    _, start = read(spki, start)    # algorithm SEQUENCE
    start, end = read(spki, start)  # BIT STRING
    return spki[start + 1 : end]


def _pss_ocsp_response(issuer, issuer_key, leaf, *, params_tlv,
                       sign_hash, sign_mgf_hash, sign_salt_length,
                       signer_key=None, responder_cert=None, embedded=(),
                       corrupt_signature=False):
    """DER of a PSS-signed OCSP response, assembled field by field.

    cryptography's OCSPResponseBuilder cannot sign with RSA-PSS, and the
    malformed-parameter cases need byte-exact control over the
    signatureAlgorithm, so the response is assembled manually. CertID uses
    SHA-1, producedAt is stamped now, the this/nextUpdate window mirrors
    good_setup(), and the signature is produced with the given PSS settings
    so well-formed responses verify end to end.
    """
    signer_key = signer_key or issuer_key
    responder_cert = responder_cert or issuer
    name_hash = hashlib.sha1(issuer.subject.public_bytes()).digest()
    key_hash = hashlib.sha1(_spk_bits(issuer)).digest()
    cert_id = _seq(
        _hash_alg_id("sha1"),
        _tlv(0x04, name_hash),
        _tlv(0x04, key_hash),
        _der_int(leaf.serial_number),
    )
    single = _seq(
        cert_id,
        _tlv(0x80, b""),  # certStatus: good
        _tlv(0x18, (NOW - timedelta(hours=1)).strftime(_GENTIME).encode()),
        _explicit(0, _tlv(0x18, (NOW + timedelta(days=7))
                          .strftime(_GENTIME).encode())),
    )
    responder_key_hash = hashlib.sha1(_spk_bits(responder_cert)).digest()
    tbs = _seq(
        _explicit(2, _tlv(0x04, responder_key_hash)),  # responderID byKey
        _tlv(0x18, datetime.now(timezone.utc).strftime(_GENTIME).encode()),
        _seq(single),
    )
    signature = signer_key.sign(
        tbs,
        padding.PSS(mgf=padding.MGF1(sign_mgf_hash()),
                    salt_length=sign_salt_length),
        sign_hash(),
    )
    if corrupt_signature:
        signature = signature[:-1] + bytes([signature[-1] ^ 0x01])
    parameters = () if params_tlv is None else (params_tlv,)
    sig_alg = _seq(_der_oid(_PSS_OID), *parameters)
    basic_fields = [tbs, sig_alg, _tlv(0x03, b"\x00" + signature)]
    if embedded:
        basic_fields.append(_explicit(0, _seq(*(
            c.public_bytes(serialization.Encoding.DER) for c in embedded))))
    basic = _seq(*basic_fields)
    return _seq(
        _tlv(0x0A, b"\x00"),  # responseStatus: successful
        _explicit(0, _seq(_der_oid(_OCSP_BASIC_OID), _tlv(0x04, basic))),
    )


def pss_setup(**resp_kwargs):
    root, root_key = _rsa_root()
    leaf, _ = _rsa_leaf("PSS Root CA", root_key)
    der = _pss_ocsp_response(root, root_key, leaf, **resp_kwargs)
    return root, leaf, base64.b64encode(der).decode()


# -- happy paths -------------------------------------------------------------


def test_pss_explicit_params_verify():
    root, leaf, b64 = pss_setup(
        params_tlv=_pss_params("sha256", "sha256", 32),
        sign_hash=hashes.SHA256, sign_mgf_hash=hashes.SHA256,
        sign_salt_length=32,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is True
    assert body["reason"] == "ok"
    assert body["signer_type"] == "issuer"
    assert body["issuer_fingerprint"] == fp(root)


def test_pss_hash_and_mgf1_combinations():
    # The main hash and the MGF1 hash are independent fields of the params;
    # every combination must be taken from the parsed parameters.
    for hash_name, mgf_name, salt in (
        ("sha256", "sha256", 32),
        ("sha384", "sha256", 48),
        ("sha256", "sha512", 32),
        ("sha512", "sha224", 64),
        ("sha224", "sha224", 28),
    ):
        root, leaf, b64 = pss_setup(
            params_tlv=_pss_params(hash_name, mgf_name, salt),
            sign_hash=_PSS_HASHES[hash_name],
            sign_mgf_hash=_PSS_HASHES[mgf_name],
            sign_salt_length=salt,
        )
        r = ocsp_precheck([leaf, root], leaf, b64)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["eligible"] is True, (hash_name, mgf_name)
        assert body["reason"] == "ok"


def test_pss_non_default_salt_lengths():
    for salt in (0, 1, 7, 33, 64, 100):
        root, leaf, b64 = pss_setup(
            params_tlv=_pss_params("sha256", "sha256", salt),
            sign_hash=hashes.SHA256, sign_mgf_hash=hashes.SHA256,
            sign_salt_length=salt,
        )
        r = ocsp_precheck([leaf, root], leaf, b64)
        assert r.status_code == 200, r.text
        assert r.json()["eligible"] is True, salt


def test_pss_default_params_empty_sequence():
    # An empty RSASSA-PSS-params SEQUENCE selects every RFC 4055 default:
    # SHA-1, MGF1-with-SHA-1, salt length 20, trailerFieldBC.
    root, leaf, b64 = pss_setup(
        params_tlv=_seq(),
        sign_hash=hashes.SHA1, sign_mgf_hash=hashes.SHA1, sign_salt_length=20,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_pss_default_params_absent():
    # No parameters element at all: the same RFC 4055 defaults apply.
    root, leaf, b64 = pss_setup(
        params_tlv=None,
        sign_hash=hashes.SHA1, sign_mgf_hash=hashes.SHA1, sign_salt_length=20,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_pss_explicit_trailer_field_bc():
    root, leaf, b64 = pss_setup(
        params_tlv=_pss_params("sha256", "sha256", 32, trailer=1),
        sign_hash=hashes.SHA256, sign_mgf_hash=hashes.SHA256,
        sign_salt_length=32,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_pss_delegated_responder():
    root, root_key = _rsa_root()
    leaf, _ = _rsa_leaf("PSS Root CA", root_key)
    responder, responder_key = _rsa_responder("PSS Root CA", root_key)
    der = _pss_ocsp_response(
        root, root_key, leaf,
        params_tlv=_pss_params("sha256", "sha256", 32),
        sign_hash=hashes.SHA256, sign_mgf_hash=hashes.SHA256,
        sign_salt_length=32,
        signer_key=responder_key, responder_cert=responder,
        embedded=(responder,),
    )
    r = ocsp_precheck([leaf, root], leaf, base64.b64encode(der).decode())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is True
    assert body["signer_type"] == "responder_certificate"
    assert body["signer_fingerprint"] == fp(responder)


def test_pss_response_with_pss_signed_bundle():
    # The leaf/issuer certificates themselves are PSS-signed; issuance edges
    # and the response signature must both still verify.
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    root_key = _rsa_key()
    root = (
        x509.CertificateBuilder()
        .subject_name(_dn("PSS Root CA"))
        .issuer_name(_dn("PSS Root CA"))
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=30))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .sign(root_key, hashes.SHA256(), rsa_padding=pss)
    )
    leaf_key = _rsa_key()
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_dn("api.example.com"))
        .issuer_name(_dn("PSS Root CA"))
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=30))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .sign(root_key, hashes.SHA256(), rsa_padding=pss)
    )
    der = _pss_ocsp_response(
        root, root_key, leaf,
        params_tlv=_pss_params("sha256", "sha256", 32),
        sign_hash=hashes.SHA256, sign_mgf_hash=hashes.SHA256,
        sign_salt_length=32,
    )
    r = ocsp_precheck([leaf, root], leaf, base64.b64encode(der).decode())
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


# -- signature_invalid (params parse, but the signature does not verify) -----


def test_pss_signature_mismatch():
    root, leaf, b64 = pss_setup(
        params_tlv=_pss_params("sha256", "sha256", 32),
        sign_hash=hashes.SHA256, sign_mgf_hash=hashes.SHA256,
        sign_salt_length=32,
        corrupt_signature=True,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "signature_invalid"


def test_pss_signature_uses_parsed_params_not_claimed_hash():
    # Signed with SHA-384 while the params claim SHA-256: verification with
    # the parsed parameters must fail cleanly, not crash.
    root, root_key = _rsa_root()
    leaf, _ = _rsa_leaf("PSS Root CA", root_key)
    der = _pss_ocsp_response(
        root, root_key, leaf,
        params_tlv=_pss_params("sha256", "sha256", 32),
        sign_hash=hashes.SHA384, sign_mgf_hash=hashes.SHA384,
        sign_salt_length=48,
    )
    r = ocsp_precheck([leaf, root], leaf, base64.b64encode(der).decode())
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "signature_invalid"


# -- malformed params that still parse as an OCSP response -------------------


def test_pss_unknown_hash_oid():
    params = _seq(_explicit(0, _seq(_der_oid("1.2.840.113549.2.5"), _NULL)))
    root, leaf, b64 = pss_setup(
        params_tlv=params,
        sign_hash=hashes.SHA256, sign_mgf_hash=hashes.SHA256,
        sign_salt_length=32,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "signature_invalid"


def test_pss_unknown_mgf_oid():
    params = _seq(_explicit(
        1, _seq(_der_oid("1.2.840.113549.1.1.9"), _hash_alg_id("sha256"))))
    root, leaf, b64 = pss_setup(
        params_tlv=params,
        sign_hash=hashes.SHA256, sign_mgf_hash=hashes.SHA256,
        sign_salt_length=32,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "signature_invalid"


def test_pss_trailer_field_not_bc():
    root, leaf, b64 = pss_setup(
        params_tlv=_pss_params("sha256", "sha256", 32, trailer=2),
        sign_hash=hashes.SHA256, sign_mgf_hash=hashes.SHA256,
        sign_salt_length=32,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "signature_invalid"


# -- malformed params that fail OCSP parsing altogether ----------------------


def test_pss_malformed_params_fail_response_parse():
    cases = {
        "params_not_a_sequence": _der_int(5),
        "duplicate_hash_field": _seq(
            _explicit(0, _hash_alg_id("sha256")),
            _explicit(0, _hash_alg_id("sha256")),
        ),
        "negative_salt_length": _seq(_explicit(2, _tlv(0x02, b"\xff"))),
        "salt_length_out_of_range": _seq(
            _explicit(2, _tlv(0x02, b"\x00\x80\x00\x00\x00"))),  # 2**31
        "unknown_params_field": _seq(_explicit(4, _der_int(1))),
        "hash_field_not_an_algorithm_id": _seq(_explicit(0, _der_int(7))),
    }
    for name, params in cases.items():
        root, leaf, b64 = pss_setup(
            params_tlv=params,
            sign_hash=hashes.SHA256, sign_mgf_hash=hashes.SHA256,
            sign_salt_length=32,
        )
        r = ocsp_precheck([leaf, root], leaf, b64)
        assert r.status_code == 200, name
        body = r.json()
        assert body["eligible"] is False
        assert body["reason"] == "invalid_ocsp_response", name


# ---------------------------------------------------------------------------
# RSASSA-PSS-params parser (unit level)
#
# cryptography's loader rejects some malformed parameters before the precheck
# sees them; these tests pin the parser's own strictness for the same classes
# (and for anything a future loader may let through).
# ---------------------------------------------------------------------------


def _pss_der(params_tlv):
    root, root_key = _rsa_root()
    leaf, _ = _rsa_leaf("PSS Root CA", root_key)
    return _pss_ocsp_response(
        root, root_key, leaf,
        params_tlv=params_tlv,
        sign_hash=hashes.SHA256, sign_mgf_hash=hashes.SHA256,
        sign_salt_length=32,
    )


def test_pss_parser_reads_explicit_and_default_params():
    hash_algo, pss = _pss_signature_parameters(
        _pss_der(_pss_params("sha384", "sha512", 48)))
    assert isinstance(hash_algo, hashes.SHA384)
    assert pss._salt_length == 48
    assert isinstance(pss._mgf._algorithm, hashes.SHA512)

    for params_tlv in (_seq(), None):  # empty or absent: RFC 4055 defaults
        hash_algo, pss = _pss_signature_parameters(_pss_der(params_tlv))
        assert isinstance(hash_algo, hashes.SHA1)
        assert pss._salt_length == 20
        assert isinstance(pss._mgf._algorithm, hashes.SHA1)


def test_pss_parser_rejects_unknown_oids():
    unknown_hash = _seq(_explicit(
        0, _seq(_der_oid("1.2.840.113549.2.5"), _NULL)))  # md5
    assert _pss_signature_parameters(_pss_der(unknown_hash)) is None
    unknown_mgf = _seq(_explicit(
        1, _seq(_der_oid("1.2.840.113549.1.1.9"), _hash_alg_id("sha256"))))
    assert _pss_signature_parameters(_pss_der(unknown_mgf)) is None


def test_pss_parser_rejects_duplicate_and_misordered_fields():
    duplicate = _seq(_explicit(0, _hash_alg_id("sha256")),
                     _explicit(0, _hash_alg_id("sha256")))
    assert _pss_signature_parameters(_pss_der(duplicate)) is None
    misordered = _seq(_explicit(1, _mgf1_alg_id("sha256")),
                      _explicit(0, _hash_alg_id("sha256")))
    assert _pss_signature_parameters(_pss_der(misordered)) is None
    unknown_field = _seq(_explicit(4, _der_int(1)))
    assert _pss_signature_parameters(_pss_der(unknown_field)) is None


def test_pss_parser_rejects_out_of_range_fields():
    negative_salt = _seq(_explicit(2, _tlv(0x02, b"\xff")))
    assert _pss_signature_parameters(_pss_der(negative_salt)) is None
    bad_trailer = _pss_params("sha256", "sha256", 32, trailer=2)
    assert _pss_signature_parameters(_pss_der(bad_trailer)) is None
    negative_trailer = _seq(_explicit(3, _tlv(0x02, b"\xff")))
    assert _pss_signature_parameters(_pss_der(negative_trailer)) is None


def test_pss_parser_rejects_illegal_tlv():
    # Truncated field content: [2] declares 5 content bytes, 2 present.
    truncated = _seq(b"\xa2\x05\x02\x01")
    assert _pss_signature_parameters(_pss_der(truncated)) is None
    # Non-minimal long-form length on the parameters SEQUENCE itself.
    inner = _pss_params("sha256", "sha256", 32)[2:]
    non_minimal = bytes([0x30, 0x81, len(inner)]) + inner
    assert _pss_signature_parameters(_pss_der(non_minimal)) is None
    # Indefinite length is not DER.
    indefinite = bytes([0x30, 0x80]) + inner + b"\x00\x00"
    assert _pss_signature_parameters(_pss_der(indefinite)) is None
    # Non-minimally encoded INTEGER (unnecessary leading zero).
    padded_int = _seq(_explicit(2, _tlv(0x02, b"\x00\x14")))
    assert _pss_signature_parameters(_pss_der(padded_int)) is None
