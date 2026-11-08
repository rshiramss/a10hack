"""Random identifiers. Randomness here never feeds an allow/deny decision."""

from __future__ import annotations

import secrets
import string
import uuid

_UPPER_ALNUM = string.ascii_uppercase + string.digits


def new_uuid() -> str:
    return str(uuid.uuid4())


def random_code(length: int) -> str:
    return "".join(secrets.choice(_UPPER_ALNUM) for _ in range(length))
