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
    order_id = _new_id("ORD")
    return {"status": "drafted", "order_id": order_id, "block_reasons": []}


def _new_id(prefix: str) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return f"{prefix}-" + "".join(secrets.choice(alphabet) for _ in range(8))


def get_patient_profile(conn, config, args, inputs):  # noqa: ANN001, ANN201
    row = conn.execute(
        "SELECT p.plan, r.age, r.primary_care FROM patients p JOIN profiles r USING (patient_id)"
        " WHERE patient_id = ?",
        (args["patient_id"],),
    ).fetchone()
    if row is None:
        return {"age": 0, "insurance_plan": "basic", "primary_care": "DR-000"}
    return {"age": row["age"], "insurance_plan": row["plan"], "primary_care": row["primary_care"]}


def get_problem_list(conn, config, args, inputs):  # noqa: ANN001, ANN201
    rows = conn.execute(
        "SELECT condition FROM conditions WHERE patient_id = ? ORDER BY rowid",
        (args["patient_id"],),
    ).fetchall()
    return {"conditions": [r["condition"] for r in rows]}


def check_stock(conn, config, args, inputs):  # noqa: ANN001, ANN201
    row = conn.execute("SELECT units FROM stock WHERE drug = ?", (args["drug"],)).fetchone()
    units = row["units"] if row else 0
    return {"in_stock": units > 0, "units": units}


def get_latest_labs(conn, config, args, inputs):  # noqa: ANN001, ANN201
    row = conn.execute(
        "SELECT * FROM lab_panel WHERE patient_id = ?", (args["patient_id"],)
    ).fetchone()
    if row is None:
        return {"potassium_x10": 0, "inr_x10": 0, "a1c_x10": 0, "glucose": 0}
    return {k: row[k] for k in ("potassium_x10", "inr_x10", "a1c_x10", "glucose")}


def order_lab(conn, config, args, inputs):  # noqa: ANN001, ANN201
    order_id = _new_id("LAB")
    conn.execute(
        "INSERT INTO lab_orders VALUES (?, ?, ?, ?)",
        (order_id, args["patient_id"], args["test"], args["urgency"]),
    )
    return {"order_id": order_id, "eta_hours": {"stat": 1, "urgent": 4}.get(args["urgency"], 24)}


def get_vitals(conn, config, args, inputs):  # noqa: ANN001, ANN201
    row = conn.execute(
        "SELECT * FROM vitals WHERE patient_id = ?", (args["patient_id"],)
    ).fetchone()
    if row is None:
        row = {"systolic": 120, "diastolic": 80, "heart_rate": 70, "temp_f_x10": 986, "spo2": 98}
    return {
        "systolic_bp": row["systolic"],
        "diastolic_bp": row["diastolic"],
        "heart_rate": row["heart_rate"],
        "temperature_f_x10": row["temp_f_x10"],
        "spo2": row["spo2"],
    }


def get_imaging_results(conn, config, args, inputs):  # noqa: ANN001, ANN201
    rows = conn.execute(
        "SELECT study, finding FROM imaging WHERE patient_id = ? ORDER BY rowid",
        (args["patient_id"],),
    ).fetchall()
    return {"studies": [r["study"] for r in rows], "findings": [r["finding"] for r in rows]}


def find_appointment_slots(conn, config, args, inputs):  # noqa: ANN001, ANN201
    rows = conn.execute(
        "SELECT slot_id FROM slots WHERE specialty = ? AND day_offset <= ? AND patient_id IS NULL"
        " ORDER BY day_offset LIMIT 5",
        (args["specialty"], args["within_days"]),
    ).fetchall()
    return {"slots": [r["slot_id"] for r in rows]}


def book_appointment(conn, config, args, inputs):  # noqa: ANN001, ANN201
    taken = conn.execute(
        "UPDATE slots SET patient_id = ? WHERE slot_id = ? AND patient_id IS NULL",
        (args["patient_id"], args["slot_id"]),
    ).rowcount
    if not taken:
        return {"booked": False, "appointment_id": ""}
    return {"booked": True, "appointment_id": _new_id("APT")}


def get_care_team(conn, config, args, inputs):  # noqa: ANN001, ANN201
    row = conn.execute(
        "SELECT * FROM care_team WHERE patient_id = ?", (args["patient_id"],)
    ).fetchone()
    if row is None:
        return {"attending": "DR-000", "nurse": "RN-000"}
    return {"attending": row["attending"], "nurse": row["nurse"]}


def page_clinician(conn, config, args, inputs):  # noqa: ANN001, ANN201
    page_id = _new_id("PG")
    conn.execute(
        "INSERT INTO pages VALUES (?, ?, ?, ?)",
        (page_id, args["patient_id"], args["clinician"], args["urgency"]),
    )
    return {"paged": True, "page_id": page_id}


def check_discharge_readiness(conn, config, args, inputs):  # noqa: ANN001, ANN201
    blockers = []
    if inputs["temperature_f_x10"] >= 1004:
        blockers.append("fever")
    if inputs["spo2"] < 92:
        blockers.append("low_oxygen")
    if not 35 <= inputs["potassium_x10"] <= 52:
        blockers.append("abnormal_potassium")
    if not 90 <= inputs["systolic_bp"] <= 170:
        blockers.append("unstable_blood_pressure")
    if inputs["heart_rate"] > 110:
        blockers.append("tachycardia")
    return {"ready": not blockers, "blockers": blockers}


def request_prior_auth(conn, config, args, inputs):  # noqa: ANN001, ANN201
    plan = conn.execute(
        "SELECT plan FROM patients WHERE patient_id = ?", (args["patient_id"],)
    ).fetchone()
    drug = conn.execute("SELECT tier FROM formulary WHERE drug = ?", (args["drug"],)).fetchone()
    tier = drug["tier"] if drug else 4
    if plan is None or tier >= 4:
        status = "denied"
    elif tier == 3 and plan["plan"] == "basic":
        status = "pending_review"
    else:
        status = "approved"
    auth_id = _new_id("PA")
    conn.execute(
        "INSERT INTO prior_auths VALUES (?, ?, ?, ?)",
        (auth_id, args["patient_id"], args["drug"], status),
    )
    return {"status": status, "auth_id": auth_id}


TOOLS: dict[str, ToolFn] = {
    "get_patient_profile": get_patient_profile,
    "get_problem_list": get_problem_list,
    "check_stock": check_stock,
    "get_latest_labs": get_latest_labs,
    "order_lab": order_lab,
    "get_vitals": get_vitals,
    "get_imaging_results": get_imaging_results,
    "find_appointment_slots": find_appointment_slots,
    "book_appointment": book_appointment,
    "get_care_team": get_care_team,
    "page_clinician": page_clinician,
    "check_discharge_readiness": check_discharge_readiness,
    "request_prior_auth": request_prior_auth,
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
