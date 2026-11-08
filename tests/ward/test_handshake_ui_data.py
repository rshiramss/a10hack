"""Handshake visualizer data: inspector fields present, secrets absent."""

from __future__ import annotations

import json
import re

import pytest

from tests.ward.test_ward import Caller, run_plan, rx_plan
from ward.config import load_config
from ward.gateway import Gateway

CFG = load_config()
SECRET_PATTERNS = [
    re.compile(r"BEGIN (?:PRIVATE|PUBLIC) KEY"),
    re.compile(r"seal_key"),
    re.compile(r"proof_key"),
    re.compile(r"wb1\."),  # full badge token prefix
    re.compile(r"client_secret"),
]


def test_successful_consult_handshake_fields() -> None:
    gw = Gateway(CFG, sleep=lambda _s: None)
    gw.settings["approvals_enabled"] = False
    master = Caller(gw, CFG.master_role)
    run_id, _ = run_plan(gw, master, rx_plan("P003", "amoxicillin", 1500)[:1])
    snap = gw.snapshot()
    run = next(r for r in snap["runs"] if r["run_id"] == run_id)
    step = run["steps"][0]
    hs = step["handshake"]
    assert hs["lanes"] == ["caller", "gateway", "specialist"]
    assert hs["master_saw"] is not None
    ids = [h["id"] for h in hs["hops"]]
    assert "delegation" in ids and "sealed" in ids and "typed_output" in ids
    sealed = next(h for h in hs["hops"] if h["id"] == "sealed")
    assert sealed["inspector"]["ciphertext_prefix16"]
    assert len(sealed["inspector"]["ciphertext_prefix16"]) == 32
    delegation = next(h for h in hs["hops"] if h["id"] == "delegation")
    claims = delegation["inspector"]["delegation_claims"]
    assert claims["tool"] == "get_allergies"
    assert "sub" in claims and "aud" in claims
    blob = json.dumps(snap)
    for pat in SECRET_PATTERNS:
        assert not pat.search(blob), pat.pattern


def test_output_rejected_stops_at_typed_output() -> None:
    from ward.gateway import Denied

    gw = Gateway(CFG, sleep=lambda _s: None)
    gw.settings["approvals_enabled"] = False
    master = Caller(gw, CFG.master_role)
    # P007's med list carries injected text; get_active_medications fails typed output.
    run_id = gw.start_run(master("start_run"), "bad-output")
    plan = gw.declare_plan(
        master("declare_plan"),
        run_id,
        [
            {
                "agent": "MedHistoryAgent",
                "tool": "get_active_medications",
                "args": {"patient_id": "P007"},
            }
        ],
    )
    with pytest.raises(Denied, match="DENY_OUTPUT_SCHEMA"):
        gw.consult(master("consult"), plan["leases"][0]["lease_id"])

    snap = gw.snapshot()
    run = next(r for r in snap["runs"] if r["run_id"] == run_id)
    hs = run["steps"][0]["handshake"]
    typed = next(h for h in hs["hops"] if h["id"] == "typed_output")
    assert typed["status"] == "fail"
    assert all(h["status"] == "ok" for h in hs["hops"] if h["id"] != "typed_output")
    assert hs["master_saw"] is None
    blob = json.dumps(hs)
    for pat in SECRET_PATTERNS:
        assert not pat.search(blob), pat.pattern
