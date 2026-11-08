"""Tool name -> implementation. Every config tool except declare_plan must be here."""

from __future__ import annotations

from badge.config import TrialConfig
from badge.tools import adjudicator, assessor, monitor, pharmacist, platform
from badge.tools.base import ToolFunction

TOOL_FUNCTIONS: dict[str, ToolFunction] = {
    "list_my_tools": platform.list_my_tools,
    "get_my_status": platform.get_my_status,
    "get_assignment": pharmacist.get_assignment,
    "dispense_kit": pharmacist.dispense_kit,
    "open_patient_visit": assessor.open_patient_visit,
    "record_outcome": assessor.record_outcome,
    "submit": assessor.submit,
    "compare_reads": adjudicator.compare_reads,
    "view_audit": monitor.view_audit,
    "revoke_badge": monitor.revoke_badge,
    "flag_outcomes": monitor.flag_outcomes,
    "request_emergency_unblind": monitor.request_emergency_unblind,
    "approve_emergency_unblind": monitor.approve_emergency_unblind,
    "view_emergency_unblind": monitor.view_emergency_unblind,
}

PIPELINE_HANDLED = frozenset({"declare_plan"})


def check_registry(config: TrialConfig) -> None:
    """Fail at startup if config and code disagree about which tools exist."""
    configured = set(config.tools) - PIPELINE_HANDLED
    implemented = set(TOOL_FUNCTIONS)
    if configured != implemented:
        raise ValueError(
            f"config/code tool mismatch: missing={sorted(configured - implemented)}"
            f" extra={sorted(implemented - configured)}"
        )
