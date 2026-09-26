"""COSE_Sign1 analysis on top of the strict deterministic-CBOR decoder.

The Sig_structure used for Ed25519 verification is built from the *raw*
protected-header bytes and the *raw* payload bytes exactly as they
appeared in the submitted package — never from re-encoded parse trees.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import cbor_strict
from .cbor_strict import CBOR, CBORError, Tagged

COSE_SIGN1_TAG = 18
ALG_EDDSA = -8
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64

HEADER_LABEL_NAMES = {
    1: "alg",
    2: "crit",
    3: "content type",
    4: "kid",
    5: "IV",
    6: "Partial IV",
    7: "countersign",
}

ALG_NAMES = {
    -7: "ES256",
    -8: "EdDSA",
    -35: "ES384",
    -36: "ES512",
    -37: "PS256",
    -38: "PS384",
    -39: "PS512",
    -46: "ES256K",
    -47: "ES256K",
}


def _encode_head(major: int, arg: int) -> bytes:
    if arg < 24:
        return bytes([(major << 5) | arg])
    if arg < 0x100:
        return bytes([(major << 5) | 24, arg])
    if arg < 0x10000:
        return bytes([(major << 5) | 25]) + arg.to_bytes(2, "big")
    if arg < 0x100000000:
        return bytes([(major << 5) | 26]) + arg.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + arg.to_bytes(8, "big")


def _encode_bstr(content: bytes) -> bytes:
    return _encode_head(2, len(content)) + content


def build_sig_structure(protected: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    """RFC 8152 section 4.4 Sig_structure for the Signature1 context.

    ``protected`` and ``payload`` must be the raw byte-string *contents*
    lifted from the submitted package, not re-encoded parse results.
    """
    return (
        _encode_head(4, 4)
        + _encode_head(3, 10) + b"Signature1"
        + _encode_bstr(protected)
        + _encode_bstr(external_aad)
        + _encode_bstr(payload)
    )


@dataclass
class PackageAnalysis:
    reasons: list[str] = field(default_factory=list)
    protected_headers: Optional[dict] = None
    protected_raw_hex: Optional[str] = None
    payload_sha256: Optional[str] = None
    payload_hex: Optional[str] = None
    payload_json: Optional[Any] = None
    signature_hex: Optional[str] = None
    signature_valid: Optional[bool] = None

    @property
    def accepted(self) -> bool:
        return not self.reasons and self.signature_valid is True


def analyze_package(
    package: bytes,
    public_key: Optional[bytes],
    key_error: Optional[str],
) -> PackageAnalysis:
    """Strictly parse and verify a COSE_Sign1 calibration package.

    Every observed defect is appended to ``reasons``; the package is
    accepted only when no reason was recorded and the Ed25519 signature
    verifies against the raw bytes.
    """
    result = PackageAnalysis()
    reasons = result.reasons
    if key_error:
        reasons.append(key_error)

    # ---- stage 1: strict deterministic CBOR -------------------------------
    try:
        top = cbor_strict.decode(package)
    except CBORError as exc:
        reasons.append(f"CBOR: {exc}")
        return result

    # ---- stage 2: COSE_Sign1 envelope shape -------------------------------
    item = top
    if item.major == 6:
        tagged: Tagged = item.value
        if tagged.tag != COSE_SIGN1_TAG:
            reasons.append(
                f"unexpected CBOR tag {tagged.tag}; COSE_Sign1 uses tag 18"
            )
            return result
        item = tagged.item
        if item.major == 6:
            reasons.append("nested CBOR tags around COSE_Sign1 are not accepted")
            return result

    if item.major != 4:
        reasons.append("COSE_Sign1 must be a CBOR array")
        return result
    if len(item.value) != 4:
        reasons.append(
            f"COSE_Sign1 array must have 4 elements, found {len(item.value)}"
        )
        return result

    protected_el, unprotected_el, payload_el, signature_el = item.value

    structure_ok = True
    if protected_el.major != 2:
        reasons.append("element 0 (protected headers) must be a byte string")
        structure_ok = False
    if unprotected_el.major != 5:
        reasons.append("element 1 (unprotected headers) must be a map")
        structure_ok = False
    if payload_el.major != 2:
        if payload_el.major == 7 and payload_el.value is None:
            reasons.append(
                "detached payloads (nil) are not supported; payload must be a byte string"
            )
        else:
            reasons.append("element 2 (payload) must be a byte string")
        structure_ok = False
    if signature_el.major != 2:
        reasons.append("element 3 (signature) must be a byte string")
        structure_ok = False
    if not structure_ok:
        return result

    # ---- stage 3: protected headers ---------------------------------------
    protected_bytes: bytes = protected_el.value
    result.protected_raw_hex = protected_bytes.hex()
    protected_map: Optional[dict] = {}
    if protected_bytes:
        try:
            ph = cbor_strict.decode(protected_bytes)
        except CBORError as exc:
            reasons.append(
                f"protected header block is not strict deterministic CBOR: {exc}"
            )
            protected_map = None
        else:
            if ph.major != 5:
                reasons.append("protected header block must decode to a CBOR map")
                protected_map = None
            else:
                protected_map = ph.value
    if protected_map is not None:
        result.protected_headers = headers_display(protected_map)

    if protected_map is not None:
        alg_item = protected_map.get(1)
        if alg_item is None:
            reasons.append(
                "protected headers do not declare a COSE algorithm "
                "(label 1 'alg' is missing)"
            )
        elif alg_item.major not in (0, 1):
            reasons.append(
                "COSE algorithm label (1) must carry an integer algorithm identifier"
            )
        elif alg_item.value != ALG_EDDSA:
            name = ALG_NAMES.get(alg_item.value, "unregistered")
            reasons.append(
                f"unsupported COSE algorithm {alg_item.value} ({name}); "
                "only EdDSA (-8) is permitted"
            )

    # ---- stage 4: payload must be a UTF-8 JSON object ----------------------
    payload_bytes: bytes = payload_el.value
    result.payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    result.payload_hex = payload_bytes.hex()
    try:
        payload_text = payload_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError:
        reasons.append("payload is not valid UTF-8")
        payload_text = None
    if payload_text is not None:
        try:
            payload_obj = json.loads(payload_text)
        except json.JSONDecodeError as exc:
            reasons.append(
                f"payload is not valid JSON: {exc.msg} "
                f"(line {exc.lineno} column {exc.colno})"
            )
        else:
            if not isinstance(payload_obj, dict):
                reasons.append("payload JSON must be an object at the top level")
            else:
                result.payload_json = payload_obj

    # ---- stage 5: signature shape ------------------------------------------
    signature: bytes = signature_el.value
    result.signature_hex = signature.hex()
    if len(signature) != ED25519_SIGNATURE_BYTES:
        reasons.append(
            f"Ed25519 signature must be {ED25519_SIGNATURE_BYTES} bytes, "
            f"found {len(signature)}"
        )

    # ---- stage 6: verify over the raw bytes --------------------------------
    if not reasons:
        assert public_key is not None  # key_error would have been recorded
        sig_structure = build_sig_structure(protected_bytes, payload_bytes)
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature, sig_structure
            )
            result.signature_valid = True
        except InvalidSignature:
            result.signature_valid = False
            reasons.append(
                "Ed25519 signature verification failed: signature does not match "
                "the raw protected-header bytes and payload"
            )
    return result


def headers_display(headers: dict) -> dict:
    """Render a decoded header map as a JSON-safe, reviewer-friendly dict."""
    out: dict[str, Any] = {}
    for label, item in headers.items():
        if isinstance(label, int) and label in HEADER_LABEL_NAMES:
            key = f"{label} ({HEADER_LABEL_NAMES[label]})"
        elif isinstance(label, str):
            key = f'"{label}"'
        else:
            key = str(label)
        out[key] = _display_value(label, item)
    return out


def _display_value(label: Any, item: CBOR) -> Any:
    if item.major in (0, 1):
        if label == 1 and item.value in ALG_NAMES:
            return f"{item.value} ({ALG_NAMES[item.value]})"
        return item.value
    if item.major == 2:
        return "h'" + item.value.hex() + "'"
    if item.major == 3:
        return item.value
    if item.major == 4:
        return [_display_value(None, child) for child in item.value]
    if item.major == 5:
        return headers_display(item.value)
    if item.major == 6:
        tagged: Tagged = item.value
        return {"tag": tagged.tag, "value": _display_value(None, tagged.item)}
    return item.value
