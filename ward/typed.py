"""Strict validation of typed values against config field specs. No coercion: a string
"3" is not the int 3, and nothing outside an enum or id pattern gets through."""

from __future__ import annotations

import re
from typing import Any

from ward.config import FieldSpec


def check_value(spec: FieldSpec, value: Any, where: str) -> str | None:
    """None if `value` fits `spec`, else a short reason."""
    if spec.type == "bool":
        return None if isinstance(value, bool) else f"{where}: expected true/false"
    if spec.type == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            return f"{where}: expected an integer"
        if not spec.min <= value <= spec.max:
            return f"{where}: {value} outside {spec.min}..{spec.max}"
        return None
    if spec.type == "enum":
        if not isinstance(value, str) or value not in spec.values:
            shown = str(value)[:40]
            return f"{where}: {shown!r} is not an allowed value"
        return None
    if spec.type == "id":
        if not isinstance(value, str) or len(value) > 64 or not re.fullmatch(spec.pattern, value):
            return f"{where}: {str(value)[:40]!r} doesn't match {spec.pattern}"
        return None
    if spec.type == "list":
        if not isinstance(value, list):
            return f"{where}: expected a list"
        if len(value) > spec.max_items:
            return f"{where}: more than {spec.max_items} items"
        for index, item in enumerate(value):
            problem = check_value(spec.items, item, f"{where}[{index}]")
            if problem:
                return problem
        return None
    return f"{where}: unsupported type"


def check_record(specs: dict[str, FieldSpec], record: Any, where: str) -> str | None:
    """Exactly the declared fields, each valid. Extra or missing fields are errors."""
    if not isinstance(record, dict):
        return f"{where}: expected an object"
    extra = set(record) - set(specs)
    if extra:
        return f"{where}: unexpected field {sorted(extra)[0]!r}"
    for name, spec in specs.items():
        if name not in record:
            return f"{where}: missing {name!r}"
        problem = check_value(spec, record[name], f"{where}.{name}")
        if problem:
            return problem
    return None
