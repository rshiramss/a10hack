"""Code attestation (simulated workload attestation).

An instance's measurement is a SHA-256 over the source of every function it would run
and its role's policy. The gateway computes the expected measurement for each role at
startup from the code it ships; an instance whose measurement differs gets no badge.

DEMO NOTE: here the instance reports its own measurement in-process. In production the
measurement comes from a trusted attestor (a TEE quote, a SPIFFE workload attestor, a
signed container digest), not from the workload itself. The gateway-side check is the same.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from collections.abc import Callable
from typing import Any

from ward.config import WardConfig


def measure(role: str, config: WardConfig, functions: dict[str, Callable[..., Any]]) -> str:
    spec = config.roles[role]
    policy = {
        "role": role,
        "tools": {name: repr(config.tools[name]) for name in spec.tools},
        "callable_by": list(spec.callable_by),
    }
    digest = hashlib.sha256(json.dumps(policy, sort_keys=True).encode())
    for name in sorted(functions):
        digest.update(name.encode())
        digest.update(inspect.getsource(functions[name]).encode())
    return digest.hexdigest()


def master_functions() -> dict[str, Callable[..., Any]]:
    from ward import master

    return {"MasterAgent": master.MasterAgent, "planner_prompt": master._capabilities_text}
