#!/usr/bin/env python3
"""End-to-end verification for the COSE calibration-package review service.

Order of checks (per spec):
  1. raw-byte signature verification and non-canonical-encoding rejection
     (plus tamper / signature-reuse / algorithm-declaration cases), each
     rejection re-read by review number to confirm it stays observable;
  2. build check (application modules byte-compile, page asset present);
  3. HTTP smoke (health endpoint and review page).

Exits 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import json
import os
import py_compile
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

BASE = os.environ.get("APP_BASE_URL", "http://localhost:8000").rstrip("/")
APP_SRC = Path(os.environ.get("APP_SRC", "app"))
PAGE = Path(os.environ.get("APP_PAGE", "app/static/index.html"))

RESULTS: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    line = f"[{'PASS' if ok else 'FAIL'}] {name}"
    if detail and not ok:
        line += f" — {detail}"
    print(line, flush=True)


# --------------------------------------------------------------------------
# minimal canonical CBOR encoder (test-vector construction only)
# --------------------------------------------------------------------------

def enc_head(major: int, arg: int) -> bytes:
    if arg < 24:
        return bytes([(major << 5) | arg])
    if arg < 0x100:
        return bytes([(major << 5) | 24, arg])
    if arg < 0x10000:
        return bytes([(major << 5) | 25]) + arg.to_bytes(2, "big")
    if arg < 0x100000000:
        return bytes([(major << 5) | 26]) + arg.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + arg.to_bytes(8, "big")


def enc_int(n: int) -> bytes:
    return enc_head(0, n) if n >= 0 else enc_head(1, -1 - n)


def enc_bstr(content: bytes) -> bytes:
    return enc_head(2, len(content)) + content


def enc_tstr(text: str) -> bytes:
    raw = text.encode("utf-8")
    return enc_head(3, len(raw)) + raw


def enc_array(items: list[bytes]) -> bytes:
    return enc_head(4, len(items)) + b"".join(items)


def enc_map(pairs: list[list[bytes]]) -> bytes:
    return enc_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


def enc_tag(tag: int, item: bytes) -> bytes:
    return enc_head(6, tag) + item


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    return (
        enc_head(4, 4)
        + enc_tstr("Signature1")
        + enc_bstr(protected)
        + enc_bstr(b"")
        + enc_bstr(payload)
    )


def cose_sign1(protected: bytes, payload: bytes, signature: bytes) -> bytes:
    return enc_tag(
        18, enc_array([enc_bstr(protected), enc_map([]), enc_bstr(payload), enc_bstr(signature)])
    )


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------

def http(method: str, path: str, body: dict | None = None) -> tuple[int, bytes]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def post_review(package: bytes, public_key_hex: str) -> dict:
    status, raw = http(
        "POST",
        "/api/reviews",
        {"public_key_hex": public_key_hex, "package_hex": package.hex()},
    )
    result = json.loads(raw)
    result["_status"] = status
    return result


def wait_for_health(timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _ = http("GET", "/api/health")
            if status == 200:
                return
        except urllib.error.URLError:
            pass
        time.sleep(1)
    print(f"service at {BASE} did not become healthy within {timeout:.0f}s", flush=True)
    sys.exit(1)


def expect_rejection(name: str, package: bytes, public_key_hex: str, keyword: str) -> None:
    """Submit a package, require rejection with a matching reason, then
    re-read the record to confirm the rejection stays observable."""
    try:
        result = post_review(package, public_key_hex)
    except Exception as exc:  # noqa: BLE001
        record(name, False, f"submission failed: {exc}")
        return
    reasons = result.get("reasons") or []
    ok = (
        result.get("_status") == 201
        and result.get("conclusion") == "rejected"
        and any(keyword in reason.lower() for reason in reasons)
    )
    if not ok:
        record(name, False, f"conclusion={result.get('conclusion')} reasons={reasons}")
        return
    review_id = result.get("review_id")
    status, raw = http("GET", f"/api/reviews/{review_id}")
    try:
        again = json.loads(raw)
    except json.JSONDecodeError:
        again = {}
    persisted = (
        status == 200
        and again.get("conclusion") == "rejected"
        and again.get("reasons") == reasons
    )
    record(name, persisted, "" if persisted else f"re-read of {review_id} mismatch")


# --------------------------------------------------------------------------
# 1. cryptographic / encoding checks
# --------------------------------------------------------------------------

def crypto_checks() -> None:
    key = Ed25519PrivateKey.generate()
    pub_hex = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    protected = enc_map([[enc_int(1), enc_int(-8)]])  # {1: -8}  alg = EdDSA
    # Deliberately quirky JSON: double space and kept key order. A backend
    # that re-serializes the payload before verifying would break the
    # signature; raw-byte verification accepts it.
    payload = (
        b'{"package": "IRR-CAL-2026-09", "dose":  1.25, "unit": "Gy",'
        b' "detector": "RX-7", "readings": [101, 99, 100]}'
    )
    signature = key.sign(sig_structure(protected, payload))
    good = cose_sign1(protected, payload, signature)

    result = post_review(good, pub_hex)
    ok = (
        result.get("_status") == 201
        and result.get("conclusion") == "accepted"
        and result.get("signature_valid") is True
        and result.get("reasons") == []
    )
    record(
        "raw-byte verification accepts valid package (whitespace-sensitive JSON payload)",
        ok,
        f"conclusion={result.get('conclusion')} reasons={result.get('reasons')}",
    )
    good_id = result.get("review_id")
    status, raw = http("GET", f"/api/reviews/{good_id}")
    again = json.loads(raw)
    record(
        "accepted record persists and is re-readable by review number",
        status == 200 and again.get("conclusion") == "accepted",
        f"status={status}",
    )

    # -- one payload byte changed, signature reused -------------------------
    tampered = payload.replace(b"1.25", b"1.26")
    expect_rejection(
        "single payload byte change is rejected (signature mismatch)",
        cose_sign1(protected, tampered, signature),
        pub_hex,
        "signature",
    )

    # -- signature from another package reused ------------------------------
    other_payload = b'{"package": "IRR-CAL-2026-09", "dose":  9.99, "unit": "Gy"}'
    expect_rejection(
        "reused signature from a different payload is rejected",
        cose_sign1(protected, other_payload, signature),
        pub_hex,
        "signature",
    )

    # -- non-canonical map key order (valid signature over those bytes!) ----
    protected_nc = enc_map(
        [[enc_int(3), enc_tstr("application/json")], [enc_int(1), enc_int(-8)]]
    )
    sig_nc = key.sign(sig_structure(protected_nc, payload))
    expect_rejection(
        "non-canonical protected-header key order is rejected",
        cose_sign1(protected_nc, payload, sig_nc),
        pub_hex,
        "canonical",
    )

    # -- duplicate map key ---------------------------------------------------
    protected_dup = enc_map([[enc_int(1), enc_int(-8)], [enc_int(1), enc_int(-8)]])
    sig_dup = key.sign(sig_structure(protected_dup, payload))
    expect_rejection(
        "duplicate protected-header key is rejected",
        cose_sign1(protected_dup, payload, sig_dup),
        pub_hex,
        "duplicate",
    )

    # -- non-shortest-form integer (-8 as 0x38 0x07) -------------------------
    protected_ns = enc_map([[enc_int(1), b"\x38\x07"]])
    sig_ns = key.sign(sig_structure(protected_ns, payload))
    expect_rejection(
        "non-shortest-form integer in protected header is rejected",
        cose_sign1(protected_ns, payload, sig_ns),
        pub_hex,
        "shortest",
    )

    # -- indefinite-length array (tag 18 in shortest form: 0xd2) ------------
    indefinite = (
        enc_head(6, 18)
        + b"\x9f"
        + enc_bstr(protected)
        + enc_map([])
        + enc_bstr(payload)
        + enc_bstr(signature)
        + b"\xff"
    )
    expect_rejection(
        "indefinite-length encoding is rejected",
        indefinite,
        pub_hex,
        "indefinite",
    )

    # -- algorithm not declared ----------------------------------------------
    sig_noalg = key.sign(sig_structure(b"", payload))
    expect_rejection(
        "missing alg declaration in protected headers is rejected",
        cose_sign1(b"", payload, sig_noalg),
        pub_hex,
        "algorithm",
    )

    # -- wrong algorithm (ES256 instead of EdDSA) ----------------------------
    protected_es256 = enc_map([[enc_int(1), enc_int(-7)]])
    sig_es256 = key.sign(sig_structure(protected_es256, payload))
    expect_rejection(
        "non-EdDSA algorithm is rejected",
        cose_sign1(protected_es256, payload, sig_es256),
        pub_hex,
        "eddsa",
    )

    # -- payload shape violations --------------------------------------------
    for name, bad_payload, keyword in [
        ("non-JSON payload is rejected", b"not json at all", "json"),
        ("JSON array payload is rejected (object required)", b"[1, 2, 3]", "object"),
        ("non-UTF-8 payload is rejected", b"\xff\xfe\xfd{}", "utf-8"),
    ]:
        sig_bad = key.sign(sig_structure(protected, bad_payload))
        expect_rejection(
            name,
            cose_sign1(protected, bad_payload, sig_bad),
            pub_hex,
            keyword,
        )

    # -- valid package, wrong public key --------------------------------------
    stranger = Ed25519PrivateKey.generate()
    stranger_hex = stranger.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    expect_rejection(
        "valid package under a mismatched public key is rejected",
        good,
        stranger_hex,
        "signature",
    )


# --------------------------------------------------------------------------
# 2. build check
# --------------------------------------------------------------------------

def build_checks() -> None:
    ok = True
    details = []
    sources = sorted(APP_SRC.rglob("*.py"))
    if not sources:
        ok = False
        details.append(f"no sources under {APP_SRC}")
    for source in sources:
        try:
            py_compile.compile(str(source), doraise=True)
        except py_compile.PyCompileError as exc:
            ok = False
            details.append(str(exc))
    record("build check: application modules byte-compile", ok, "; ".join(details))
    record(
        "build check: review page asset present",
        PAGE.is_file() and PAGE.stat().st_size > 0,
        f"missing {PAGE}",
    )


# --------------------------------------------------------------------------
# 3. HTTP smoke
# --------------------------------------------------------------------------

def smoke_checks() -> None:
    status, body = http("GET", "/api/health")
    record(
        "HTTP smoke: /api/health responds ok",
        status == 200 and b'"ok"' in body,
        f"status={status} body={body[:80]!r}",
    )
    status, body = http("GET", "/")
    record(
        "HTTP smoke: review page is served",
        status == 200 and "COSE".encode() in body,
        f"status={status}",
    )


def main() -> None:
    wait_for_health()
    crypto_checks()
    build_checks()
    smoke_checks()

    failed = [name for name, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed", flush=True)
    if failed:
        print("failed checks:", flush=True)
        for name in failed:
            print(f"  - {name}", flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
