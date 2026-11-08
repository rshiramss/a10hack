"""Rule-based redaction of arm-revealing side effects (section 9.4).

Access control can't stop a leak hidden inside data the agent is allowed to see: a note
saying "dry mouth" hints the patient is on the active drug. So blinded roles get visit
records with those terms replaced by [REDACTED].
"""

from __future__ import annotations

import re

from badge.config import TrialConfig

REDACTED = "[REDACTED]"

_CACHE: dict[int, tuple[TrialConfig, re.Pattern[str]]] = {}


def _pattern(config: TrialConfig) -> re.Pattern[str]:
    cached = _CACHE.get(id(config))
    if cached is None or cached[0] is not config:
        terms = "|".join(re.escape(term) for term in config.redaction_terms)
        # Optional plural suffix so "rashes" is caught as well as "rash".
        cached = (config, re.compile(rf"\b(?:{terms})(?:es|s)?\b", re.IGNORECASE))
        _CACHE[id(config)] = cached
    return cached[1]


def redact(config: TrialConfig, text: str) -> tuple[str, int]:
    """Return the redacted text and how many terms were replaced."""
    if not config.redaction_terms:
        return text, 0
    return _pattern(config).subn(REDACTED, text)
