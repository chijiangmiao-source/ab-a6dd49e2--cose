"""Strict deterministic-CBOR decoder.

Only deterministic (canonical) CBOR is accepted:

* no indefinite-length items (additional information 31 is rejected);
* integers, lengths and tag numbers must use the shortest form;
* map keys must be unique and appear in canonical order
  (shorter encoded keys first, then bytewise lexicographic);
* text strings must be valid UTF-8;
* map keys are restricted to integers and text strings (COSE profile);
* floats and exotic simple values are rejected.

Every decoded item retains its exact raw byte span so that callers can
feed the *original* bytes to cryptographic primitives instead of
re-encoding parsed objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class CBORError(ValueError):
    """The input is not strict deterministic CBOR."""


@dataclass
class Tagged:
    tag: int
    item: "CBOR"


@dataclass
class CBOR:
    major: int  # 0..7; 6 means ``value`` is a Tagged wrapper
    value: Any  # int | bytes | str | list[CBOR] | dict[key, CBOR] | Tagged | bool | None
    raw: bytes  # exact bytes of this item, head included


_MAX_DEPTH = 32


def decode(data: bytes) -> CBOR:
    """Decode one strict deterministic-CBOR item; trailing bytes are rejected."""
    if not data:
        raise CBORError("empty input")
    item, pos = _decode_item(data, 0, 0)
    if pos != len(data):
        raise CBORError(
            f"trailing bytes after top-level item ({len(data) - pos} byte(s))"
        )
    return item


def _canonical_key_lt(a: bytes, b: bytes) -> bool:
    """RFC 7049 canonical ordering: shorter first, then bytewise."""
    return (len(a), a) < (len(b), b)


def _read_argument(data: bytes, pos: int, ai: int) -> tuple[int, int]:
    """Read a head argument, enforcing shortest-form encoding."""
    if ai < 24:
        return ai, pos
    if ai == 24:
        size, minimum = 1, 24
    elif ai == 25:
        size, minimum = 2, 0x100
    elif ai == 26:
        size, minimum = 4, 0x10000
    elif ai == 27:
        size, minimum = 8, 0x100000000
    elif ai == 31:
        raise CBORError(
            "indefinite-length encoding is not allowed (deterministic CBOR required)"
        )
    else:
        raise CBORError(f"reserved additional-information value {ai}")
    if pos + size > len(data):
        raise CBORError("truncated argument bytes")
    arg = int.from_bytes(data[pos : pos + size], "big")
    if arg < minimum:
        raise CBORError(
            f"non-shortest-form integer: value {arg} must not use {size} byte(s)"
        )
    return arg, pos + size


def _decode_item(data: bytes, pos: int, depth: int) -> tuple[CBOR, int]:
    if depth > _MAX_DEPTH:
        raise CBORError("excessive nesting depth")
    if pos >= len(data):
        raise CBORError("unexpected end of input")
    start = pos
    initial = data[pos]
    pos += 1
    major = initial >> 5
    ai = initial & 0x1F

    if major == 7:
        return _decode_simple(data, start, pos, ai)

    arg, pos = _read_argument(data, pos, ai)

    if major == 0:
        return CBOR(0, arg, data[start:pos]), pos
    if major == 1:
        return CBOR(1, -1 - arg, data[start:pos]), pos
    if major == 2:
        if pos + arg > len(data):
            raise CBORError("truncated byte string")
        return CBOR(2, data[pos : pos + arg], data[start : pos + arg]), pos + arg
    if major == 3:
        if pos + arg > len(data):
            raise CBORError("truncated text string")
        chunk = data[pos : pos + arg]
        try:
            text = chunk.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise CBORError(f"text string is not valid UTF-8: {exc}") from exc
        return CBOR(3, text, data[start : pos + arg]), pos + arg
    if major == 4:
        items = []
        for _ in range(arg):
            child, pos = _decode_item(data, pos, depth + 1)
            items.append(child)
        return CBOR(4, items, data[start:pos]), pos
    if major == 5:
        result: dict[Any, CBOR] = {}
        prev_raw: bytes | None = None
        for _ in range(arg):
            key, pos = _decode_item(data, pos, depth + 1)
            if key.major not in (0, 1, 3):
                raise CBORError(
                    "map keys must be integers or text strings in this profile"
                )
            if prev_raw is not None:
                if key.raw == prev_raw:
                    raise CBORError(f"duplicate map key {key.value!r}")
                if not _canonical_key_lt(prev_raw, key.raw):
                    raise CBORError(
                        "map keys are not in canonical order "
                        "(shorter encodings first, then bytewise lexicographic)"
                    )
            prev_raw = key.raw
            value, pos = _decode_item(data, pos, depth + 1)
            result[key.value] = value
        return CBOR(5, result, data[start:pos]), pos
    # major == 6 (tag)
    inner, pos = _decode_item(data, pos, depth + 1)
    return CBOR(6, Tagged(arg, inner), data[start:pos]), pos


def _decode_simple(
    data: bytes, start: int, pos: int, ai: int
) -> tuple[CBOR, int]:
    if ai == 20:
        return CBOR(7, False, data[start:pos]), pos
    if ai == 21:
        return CBOR(7, True, data[start:pos]), pos
    if ai == 22:
        return CBOR(7, None, data[start:pos]), pos
    if ai == 23:
        raise CBORError("simple value 'undefined' is not permitted in this profile")
    if ai == 24:
        raise CBORError("two-byte simple values are not permitted in this profile")
    if ai in (25, 26, 27):
        raise CBORError("floating-point numbers are not permitted in this profile")
    if ai == 31:
        raise CBORError("unexpected break byte outside an indefinite-length item")
    raise CBORError(f"reserved additional-information value {ai}")
