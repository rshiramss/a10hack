"""Canonical JSON and hashing helpers shared by the audit log and idempotency store."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Sorted keys, no whitespace, UTF-8 safe. Same value -> same string, always."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_value(value: Any) -> str:
    return sha256_hex(canonical_json(value))
