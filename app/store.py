"""SQLite persistence for review records.

Every submission — accepted or rejected — is persisted so that rejection
records remain observable and re-readable by review number.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at         TEXT NOT NULL,
    public_key_hex     TEXT NOT NULL,
    package_sha256     TEXT NOT NULL,
    protected_headers  TEXT,
    protected_raw_hex  TEXT,
    payload_sha256     TEXT,
    payload_hex        TEXT,
    payload_json       TEXT,
    signature_hex      TEXT,
    signature_valid    INTEGER,
    conclusion         TEXT NOT NULL,
    reasons            TEXT NOT NULL
);
"""

_lock = threading.Lock()


def init(path: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with _connect(path) as conn:
        conn.executescript(_SCHEMA)


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def insert(path: str, record: dict[str, Any]) -> int:
    """Insert a review record and return its integer id."""
    with _lock, _connect(path) as conn:
        cur = conn.execute(
            """
            INSERT INTO reviews (
                created_at, public_key_hex, package_sha256,
                protected_headers, protected_raw_hex,
                payload_sha256, payload_hex, payload_json,
                signature_hex, signature_valid,
                conclusion, reasons
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["created_at"],
                record["public_key_hex"],
                record["package_sha256"],
                _dump(record.get("protected_headers")),
                record.get("protected_raw_hex"),
                record.get("payload_sha256"),
                record.get("payload_hex"),
                _dump(record.get("payload_json")),
                record.get("signature_hex"),
                _bool_to_int(record.get("signature_valid")),
                record["conclusion"],
                _dump(record["reasons"]),
            ),
        )
        return int(cur.lastrowid)


def fetch(path: str, review_id: int) -> Optional[dict[str, Any]]:
    with _lock, _connect(path) as conn:
        row = conn.execute(
            "SELECT * FROM reviews WHERE id = ?", (review_id,)
        ).fetchone()
    if row is None:
        return None
    return _row_to_record(dict(row))


def _row_to_record(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "review_id": format_review_id(row["id"]),
        "created_at": row["created_at"],
        "public_key_hex": row["public_key_hex"],
        "package_sha256": row["package_sha256"],
        "protected_headers": _load(row["protected_headers"]),
        "protected_raw_hex": row["protected_raw_hex"],
        "payload_sha256": row["payload_sha256"],
        "payload_hex": row["payload_hex"],
        "payload_json": _load(row["payload_json"]),
        "signature_hex": row["signature_hex"],
        "signature_valid": _int_to_bool(row["signature_valid"]),
        "conclusion": row["conclusion"],
        "reasons": _load(row["reasons"]) or [],
    }


def format_review_id(row_id: int) -> str:
    return f"RV-{row_id:06d}"


def _dump(value: Any) -> Optional[str]:
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False)


def _load(text: Optional[str]) -> Any:
    if text is None:
        return None
    return json.loads(text)


def _bool_to_int(value: Optional[bool]) -> Optional[int]:
    if value is None:
        return None
    return 1 if value else 0


def _int_to_bool(value: Optional[int]) -> Optional[bool]:
    if value is None:
        return None
    return bool(value)
