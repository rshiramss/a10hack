"""Specialist agents' atomic functions. Deterministic, no LLM, one per tool.

Each function sees only: its own role's tables, its bound args, and the typed inputs the
gateway piped in. It returns a record the gateway validates against the tool's output
schema before anything leaves the specialist.
"""

from __future__ import annotations

import secrets
import sqlite3
from collections.abc import Callable
from typing import Any

from ward.config import WardConfig
from ward.data import COPAY_BY_TIER, UNCOVERED_MONTHLY_USD

ToolFn = Callable[[sqlite3.Connection, WardConfig, dict[str, Any], dict[str, Any]], dict[str, Any]]


def _renal_band(egfr: int) -> str:
    if egfr >= 90:
        return "normal"
    if egfr >= 60:
        return "mild"
    if egfr >= 30:
        return "moderate"
    return "severe"


def find_patient(conn, config, args, inputs):  # noqa: ANN001, ANN201
    wanted = " ".join(args["name"].lower().split())
    for row in conn.execute("SELECT patient_id, name FROM patients ORDER BY patient_id"):
        full = row["name"].lower()
        if wanted in (full, full.split()[0], full.split()[-1]):
            return {"found": True, "patient_id": row["patient_id"]}
    return {"found": False, "patient_id": ""}


def get_active_medications(conn, config, args, inputs):  # noqa: ANN001, ANN201
    rows = conn.execute(
        "SELECT drug FROM med_list WHERE patient_id = ? ORDER BY rowid", (args["patient_id"],)
    ).fetchall()
    # Returned as stored. If a record holds anything but a drug code, the output schema
    # check rejects the whole result before it can reach another agent.
    return {"meds": [row["drug"] for row in rows]}


def get_allergies(conn, config, args, inputs):  # noqa: ANN001, ANN201
    rows = conn.execute(
        "SELECT allergen FROM allergies WHERE patient_id = ? ORDER BY rowid",
        (args["patient_id"],),
    ).fetchall()
    return {"allergies": [row["allergen"] for row in rows]}


def lookup_drug(conn, config, args, inputs):  # noqa: ANN001, ANN201
    row = conn.execute("SELECT * FROM formulary WHERE drug = ?", (args["drug"],)).fetchone()
    return {
        "drug": args["drug"],
        "drug_class": row["drug_class"],
        "in_formulary": bool(row["in_formulary"]),
        "max_daily_mg": row["max_daily_mg"],
        "renal_caution": bool(row["renal_caution"]),
    }


def check_interactions(conn, config, args, inputs):  # noqa: ANN001, ANN201
    rank = {name: i for i, name in enumerate(config.vocab["severity"])}
    worst, interacting = "none", []
    for other in inputs["current_meds"]:
        row = conn.execute(
            "SELECT severity FROM interactions WHERE (drug_a = ? AND drug_b = ?)"
            " OR (drug_a = ? AND drug_b = ?)",
            (args["drug"], other, other, args["drug"]),
        ).fetchone()
        if row and row["severity"] != "none":
            interacting.append(other)
            if rank[row["severity"]] > rank[worst]:
                worst = row["severity"]
    return {"worst": worst, "interacting": interacting}


def get_renal_function(conn, config, args, inputs):  # noqa: ANN001, ANN201
    row = conn.execute(
        "SELECT egfr FROM labs WHERE patient_id = ?", (args["patient_id"],)
    ).fetchone()
    egfr = row["egfr"] if row else 0
    return {"egfr": egfr, "band": _renal_band(egfr)}


def check_coverage(conn, config, args, inputs):  # noqa: ANN001, ANN201
    plan = conn.execute(
        "SELECT plan FROM patients WHERE patient_id = ?", (args["patient_id"],)
    ).fetchone()
    drug = conn.execute(
        "SELECT tier, prior_auth FROM formulary WHERE drug = ?", (args["drug"],)
    ).fetchone()
    max_tier = 2 if plan and plan["plan"] == "basic" else 3
    covered = plan is not None and drug["tier"] <= max_tier
    copay = (
        COPAY_BY_TIER.get(drug["tier"], UNCOVERED_MONTHLY_USD) if covered else UNCOVERED_MONTHLY_USD
    )
    return {
        "covered": covered,
        "tier": drug["tier"],
        "prior_auth": bool(drug["prior_auth"]),
        "monthly_copay_usd": copay,
    }


def draft_order(conn, config, args, inputs):  # noqa: ANN001, ANN201
    reasons = []
    for allergen in inputs["allergies"]:
        if inputs["drug_class"] in config.allergy_blocks.get(allergen, ()):
            reasons.append("allergy")
            break
    if inputs["interaction"] == "major":
        reasons.append("major_interaction")
    if inputs["renal_caution"] and inputs.get("renal_band") == "severe":
        reasons.append("renal")
    if args["daily_dose_mg"] > inputs["max_daily_mg"]:
        reasons.append("dose_above_max")
    if not inputs["in_formulary"]:
        reasons.append("not_in_formulary")
    if reasons:
        return {"status": "blocked", "order_id": "", "block_reasons": reasons}
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    order_id = "ORD-" + "".join(secrets.choice(alphabet) for _ in range(8))
    return {"status": "drafted", "order_id": order_id, "block_reasons": []}


TOOLS: dict[str, ToolFn] = {
    "find_patient": find_patient,
    "get_active_medications": get_active_medications,
    "get_allergies": get_allergies,
    "lookup_drug": lookup_drug,
    "check_interactions": check_interactions,
    "get_renal_function": get_renal_function,
    "check_coverage": check_coverage,
    "draft_order": draft_order,
}


def check_registry(config: WardConfig) -> None:
    missing = set(config.tools) - set(TOOLS)
    if missing:
        raise RuntimeError(f"config names tools with no implementation: {sorted(missing)}")
