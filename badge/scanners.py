"""Deterministic content scanners (section 9.3). Regex and term lists only; no ML."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from badge import reasons
from badge.config import TrialConfig
from badge.context import CallContext
from badge.decisions import Action, Allow, Decision, Deny


@dataclass(frozen=True)
class CompiledScanners:
    canary: re.Pattern[str]
    injection: tuple[re.Pattern[str], ...]
    arm_terms: re.Pattern[str]


_CACHE: dict[int, tuple[TrialConfig, CompiledScanners]] = {}


def compiled(config: TrialConfig) -> CompiledScanners:
    cached = _CACHE.get(id(config))
    if cached is None or cached[0] is not config:
        spec = config.scanners
        terms = "|".join(re.escape(term) for term in spec.arm_terms)
        scanners = CompiledScanners(
            canary=re.compile(spec.canary_pattern),
            injection=tuple(re.compile(p, re.MULTILINE) for p in spec.injection_patterns),
            arm_terms=re.compile(rf"\b(?:{terms})\b", re.IGNORECASE),
        )
        cached = (config, scanners)
        _CACHE[id(config)] = cached
    return cached[1]


def canary_pattern(config: TrialConfig) -> re.Pattern[str]:
    return compiled(config).canary


def _strings_in(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*_strings_in(k), *_strings_in(v))]
    if isinstance(value, (list, tuple)):
        return [s for item in value for s in _strings_in(item)]
    return []


def contains_canary(config: TrialConfig, value: Any) -> bool:
    """True if any string anywhere inside `value` contains a canary token."""
    pattern = compiled(config).canary
    return any(pattern.search(text) for text in _strings_in(value))


def contains_injection(config: TrialConfig, text: str) -> bool:
    return any(pattern.search(text) for pattern in compiled(config).injection)


def count_arm_terms(config: TrialConfig, text: str) -> int:
    if not config.scanners.arm_terms:
        return 0
    return len(compiled(config).arm_terms.findall(text))


def check_input_content(ctx: CallContext) -> Decision:
    """Pipeline step 10: canaries anywhere revoke; injections deny; arm terms get flagged."""
    if contains_canary(ctx.config, ctx.args):
        return Deny(reasons.DENY_CANARY, Action.REVOKE, detail="canary token in input")
    arm_term_hits = 0
    for name, arg_spec in ctx.tool_spec.args.items():
        text = ctx.args.get(name)
        if arg_spec.type != "text" or not isinstance(text, str):
            continue
        if "injection" in arg_spec.scan and contains_injection(ctx.config, text):
            return Deny(reasons.DENY_INJECTION, detail=f"injection pattern in {name}")
        if "arm_terms" in arg_spec.scan:
            arm_term_hits += count_arm_terms(ctx.config, text)
    return Allow({"arm_term_hits": arm_term_hits})
