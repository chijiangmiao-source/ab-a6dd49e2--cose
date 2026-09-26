"""HTTP API and page serving for the COSE calibration-package reviewer."""

from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import cose, store

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("REVIEW_DB", str(BASE_DIR.parent / "data" / "reviews.db"))
MAX_PACKAGE_BYTES = 1_000_000

app = FastAPI(title="Irradiation Calibration Package Review")

store.init(DB_PATH)


class ReviewRequest(BaseModel):
    public_key_hex: str
    package_hex: str


def _clean_hex(text: str) -> str:
    cleaned = re.sub(r"\s+", "", text)
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    return cleaned


@app.post("/api/reviews", status_code=201)
def submit_review(req: ReviewRequest):
    key_hex = _clean_hex(req.public_key_hex)
    key_bytes = None
    key_error = None
    try:
        candidate = bytes.fromhex(key_hex)
    except ValueError:
        key_error = "public key is not valid hexadecimal"
    else:
        if len(candidate) != cose.ED25519_PUBLIC_KEY_BYTES:
            key_error = (
                f"Ed25519 public key must be {cose.ED25519_PUBLIC_KEY_BYTES} bytes "
                f"({cose.ED25519_PUBLIC_KEY_BYTES * 2} hex chars), "
                f"got {len(candidate)} bytes"
            )
        else:
            key_bytes = candidate

    package_hex = _clean_hex(req.package_hex)
    if not package_hex:
        raise HTTPException(status_code=400, detail="package_hex must not be empty")
    try:
        package = bytes.fromhex(package_hex)
    except ValueError:
        raise HTTPException(
            status_code=400, detail="package_hex is not valid hexadecimal"
        )
    if len(package) > MAX_PACKAGE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"package exceeds {MAX_PACKAGE_BYTES} bytes",
        )

    analysis = cose.analyze_package(package, key_bytes, key_error)
    conclusion = "accepted" if analysis.accepted else "rejected"

    record = {
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "public_key_hex": key_hex.lower(),
        "package_sha256": hashlib.sha256(package).hexdigest(),
        "protected_headers": analysis.protected_headers,
        "protected_raw_hex": analysis.protected_raw_hex,
        "payload_sha256": analysis.payload_sha256,
        "payload_hex": analysis.payload_hex,
        "payload_json": analysis.payload_json,
        "signature_hex": analysis.signature_hex,
        "signature_valid": analysis.signature_valid,
        "conclusion": conclusion,
        "reasons": analysis.reasons,
    }
    row_id = store.insert(DB_PATH, record)
    record["review_id"] = store.format_review_id(row_id)
    return record


@app.get("/api/reviews/{review_id}")
def get_review(review_id: str):
    match = re.fullmatch(r"(?:RV-)?(\d{1,12})", review_id.strip(), re.IGNORECASE)
    if not match:
        raise HTTPException(status_code=400, detail="invalid review id")
    record = store.fetch(DB_PATH, int(match.group(1)))
    if record is None:
        raise HTTPException(status_code=404, detail="review not found")
    return record


@app.get("/api/health")
def health():
    try:
        store.fetch(DB_PATH, 0)  # touch the database
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=503, detail=f"database unavailable: {exc}")
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(BASE_DIR / "static" / "index.html")
