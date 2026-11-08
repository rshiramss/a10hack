"""Pydantic v2 schemas: the declare_plan input and every tool's output.

Tool *inputs* are policy, so they're generated from config by `badge.schemas`.
`declare_plan` nests steps, so its input schema lives here. Outputs are code contracts:
the output filter validates every tool result against these before it leaves the gateway.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

MAX_PLAN_STEPS_HARD_CAP = 32
MAX_NOTE_LEN = 2000

ShortStr = Annotated[str, StringConstraints(max_length=64)]
ToolName = Annotated[str, StringConstraints(pattern=r"^[a-z_]{1,64}$")]
TaskId = Annotated[str, StringConstraints(pattern=r"^T-[A-Za-z0-9-]{1,48}$")]
VisitId = Annotated[str, StringConstraints(pattern=r"^V-[0-9]{2}$")]
PatientId = Annotated[str, StringConstraints(pattern=r"^P[0-9]{3}$")]
Score = Annotated[int, Field(ge=0, le=10)]
Measure = Literal["pain_score", "mobility_score", "global_impression"]
Arm = Literal["active", "placebo"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


# ---- declare_plan input ------------------------------------------------------


class PlanStep(_StrictModel):
    tool: ToolName
    args: dict[ShortStr, ShortStr | int] = Field(max_length=16)


class DeclarePlanArgs(_StrictModel):
    task_id: TaskId
    steps: list[PlanStep] = Field(min_length=1, max_length=MAX_PLAN_STEPS_HARD_CAP)


# ---- outputs -------------------------------------------------------------------


class LeaseOut(_StrictModel):
    lease_id: str
    step_index: int
    tool: str
    bound_args: dict[str, Any]
    expires_at_ms: int


class DeclarePlanOut(_StrictModel):
    plan_id: str
    task_id: str
    expires_at_ms: int
    leases: list[LeaseOut]


class ListMyToolsOut(_StrictModel):
    tools: list[dict[str, Any]]


class TaskOut(_StrictModel):
    task_id: str
    resource_id: str
    slot: int
    status: str


class PlanProgressOut(_StrictModel):
    plan_id: str
    task_id: str
    steps_total: int
    steps_used: int
    next_tool: str | None
    expires_at_ms: int


class GetMyStatusOut(_StrictModel):
    agent_id: str
    role: str
    badge_id: str
    badge_expires_at_ms: int
    status: str
    tasks: list[TaskOut]
    active_plans: list[PlanProgressOut]


class GetAssignmentOut(_StrictModel):
    patient_id: PatientId
    visit_id: VisitId
    arm: Arm


class DispenseKitOut(_StrictModel):
    patient_id: PatientId
    visit_id: VisitId
    kit_id: Annotated[str, StringConstraints(pattern=r"^KIT-[A-Z0-9]{8}$")]
    kit_status: Literal["dispensed"]


class OpenVisitOut(_StrictModel):
    visit_id: VisitId
    patient_id: PatientId
    visit_no: int
    slot: int
    note: Annotated[str, StringConstraints(max_length=MAX_NOTE_LEN)]


class RecordOutcomeOut(_StrictModel):
    outcome_id: str
    visit_id: VisitId
    slot: int
    measure: Measure
    value: Score
    supersedes_id: str | None
    flagged_for_review: bool


class SubmitOut(_StrictModel):
    submission_id: str
    visit_id: VisitId
    slot: int
    measures_submitted: int


class CompareReadsOut(_StrictModel):
    visit_id: VisitId
    result: Literal["agree", "disagree"]
    max_delta: Score


class ViewAuditOut(_StrictModel):
    entries: list[dict[str, Any]]


class RevokeBadgeOut(_StrictModel):
    agent_id: str
    badges_revoked: int


class FlagOutcomesOut(_StrictModel):
    agent_id: str
    outcomes_flagged: int


class RequestUnblindOut(_StrictModel):
    request_id: str
    patient_id: PatientId
    status: Literal["pending"]


class ApproveUnblindOut(_StrictModel):
    request_id: str
    lease_id: str
    expires_at_ms: int
    outcomes_flagged: int


class ViewUnblindOut(_StrictModel):
    request_id: str
    patient_id: PatientId
    arm: Arm


OUTPUT_MODELS: dict[str, type[BaseModel]] = {
    "declare_plan": DeclarePlanOut,
    "list_my_tools": ListMyToolsOut,
    "get_my_status": GetMyStatusOut,
    "get_assignment": GetAssignmentOut,
    "dispense_kit": DispenseKitOut,
    "open_patient_visit": OpenVisitOut,
    "record_outcome": RecordOutcomeOut,
    "submit": SubmitOut,
    "compare_reads": CompareReadsOut,
    "view_audit": ViewAuditOut,
    "revoke_badge": RevokeBadgeOut,
    "flag_outcomes": FlagOutcomesOut,
    "request_emergency_unblind": RequestUnblindOut,
    "approve_emergency_unblind": ApproveUnblindOut,
    "view_emergency_unblind": ViewUnblindOut,
}
