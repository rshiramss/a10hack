"""Load and validate config/trial.yaml.

The config is the policy. Every enforcement module receives a `TrialConfig` and reads
roles, tools, workflows, handoffs, and scanners from it. Validation here fails fast at
startup so a typo in the policy never turns into a silent allow at runtime.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "trial.yaml"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ArgSpec(_Strict):
    """One tool argument (or one handoff field)."""

    type: Literal["id", "enum", "int", "text", "bool", "map"]
    pattern: str | None = None
    values: list[str] | None = None
    min: int | None = None
    max: int | None = None
    max_len: int | None = None
    optional: bool = False
    bind: bool = False
    plan_wildcard: bool = False
    scan: list[Literal["injection", "arm_terms", "canary"]] = Field(default_factory=list)
    # Only for type=map: allowed keys (an enum) and the spec every value must satisfy.
    keys: list[str] | None = None
    value_spec: ArgSpec | None = Field(default=None, alias="values_spec")

    @model_validator(mode="after")
    def _check_shape(self) -> ArgSpec:
        if self.type == "id" and not self.pattern:
            raise ValueError("id args need a pattern")
        if self.type == "enum" and not self.values:
            raise ValueError("enum args need values")
        if self.type == "int" and (self.min is None or self.max is None):
            raise ValueError("int args need min and max")
        if self.type == "text" and not self.max_len:
            raise ValueError("text args need max_len")
        if self.type == "text" and self.bind:
            raise ValueError("free-text args can never be bound in a plan")
        if self.plan_wildcard and self.type != "enum":
            raise ValueError("plan_wildcard is only allowed on enum args")
        if self.type == "map" and (not self.keys or self.value_spec is None):
            raise ValueError("map specs need keys and a value spec")
        if self.type == "map" and self.value_spec.type in ("text", "map"):
            raise ValueError("map values must be scalar typed values, never text")
        return self


class Budgets(_Strict):
    max_steps_per_plan: int = Field(ge=0)
    max_calls_per_minute: int = Field(ge=1)
    max_reads_per_task: int = Field(ge=0)
    max_denied_calls_per_badge: int = Field(ge=1)
    max_replans_per_task: int = Field(ge=0)


class RoleSpec(_Strict):
    blinded: bool
    human: bool = False
    badge_ttl_minutes: int | None = None
    tools: list[str]
    budgets: Budgets


class Precondition(_Strict):
    channel: str
    field: str
    equals: str | int | bool


class ToolSpec(_Strict):
    description: str
    planned: bool
    mutating: bool = False
    single_use: bool = False
    standing_lease: bool = False
    severity: Literal["normal", "high"] = "normal"
    workflow: str | None = None
    resource_arg: str | None = None
    patient_arg: str | None = None
    counts_as_read: bool = False
    preconditions: list[Precondition] = Field(default_factory=list)
    inputs: list[str] = Field(default_factory=list)
    produces: str | None = None
    redact_output: list[str] = Field(default_factory=list)
    lease_ttl_minutes: int | None = None
    args: dict[str, ArgSpec]

    @model_validator(mode="after")
    def _check_planned(self) -> ToolSpec:
        if self.planned and not (self.workflow and self.resource_arg):
            raise ValueError("planned tools need a workflow and a resource_arg")
        if self.resource_arg and self.resource_arg not in self.args:
            raise ValueError("resource_arg must be one of the tool's args")
        return self

    def bound_arg_names(self) -> list[str]:
        return [name for name, spec in self.args.items() if spec.bind]

    def text_arg_names(self) -> list[str]:
        return [name for name, spec in self.args.items() if spec.type == "text"]


class Transition(_Strict):
    tool: str
    from_states: list[str] = Field(alias="from")
    to: str


class ReadyWhen(_Strict):
    channel: str
    slots: list[int]
    from_state: str = Field(alias="from")
    to: str


class WorkflowSpec(_Strict):
    slotted: bool
    hold_slot: bool = False
    initial: str
    terminal: list[str]
    transitions: list[Transition]
    ready_when: ReadyWhen | None = None


class Endpoint(_Strict):
    role: str
    tool: str


class HandoffSpec(_Strict):
    producer: Endpoint
    consumer: Endpoint
    slotted: bool = False
    schema_: dict[str, ArgSpec] = Field(alias="schema")


class ScannerSpec(_Strict):
    canary_pattern: str
    arm_terms: list[str]
    injection_patterns: list[str]


class TrialConfig(_Strict):
    trial_id: str
    badge_ttl_minutes: int = Field(ge=1)
    plan_ttl_minutes: int = Field(ge=1)
    emergency_lease_ttl_minutes: int = Field(ge=1)
    agree_threshold: int = Field(ge=0, le=10)
    default_string_max_len: int = Field(ge=1)
    platform_tools: list[str]
    roles: dict[str, RoleSpec]
    tools: dict[str, ToolSpec]
    workflows: dict[str, WorkflowSpec]
    handoffs: dict[str, HandoffSpec]
    scanners: ScannerSpec
    redaction_terms: list[str]

    @model_validator(mode="after")
    def _cross_check(self) -> TrialConfig:
        for tool_name in self.platform_tools:
            if tool_name not in self.tools:
                raise ValueError(f"platform tool {tool_name!r} has no tool entry")
        for role_name, role in self.roles.items():
            for tool_name in role.tools:
                if tool_name not in self.tools:
                    raise ValueError(f"role {role_name!r} lists unknown tool {tool_name!r}")
        for tool_name, tool in self.tools.items():
            self._check_tool_references(tool_name, tool)
        for channel_id, channel in self.handoffs.items():
            if channel.producer.role not in self.roles:
                raise ValueError(f"handoff {channel_id} has unknown producer role")
            if channel.consumer.role not in self.roles:
                raise ValueError(f"handoff {channel_id} has unknown consumer role")
        return self

    def _check_tool_references(self, tool_name: str, tool: ToolSpec) -> None:
        if tool.workflow and tool.workflow not in self.workflows:
            raise ValueError(f"tool {tool_name!r} names unknown workflow {tool.workflow!r}")
        for channel_id in [*tool.inputs, *(p.channel for p in tool.preconditions)]:
            if channel_id not in self.handoffs:
                raise ValueError(f"tool {tool_name!r} names unknown channel {channel_id!r}")
        if tool.produces and tool.produces not in self.handoffs:
            raise ValueError(f"tool {tool_name!r} produces unknown channel {tool.produces!r}")

    # ---- lookups ------------------------------------------------------------

    def role(self, role_name: str) -> RoleSpec:
        return self.roles[role_name]

    def tool(self, tool_name: str) -> ToolSpec:
        return self.tools[tool_name]

    def is_platform_tool(self, tool_name: str) -> bool:
        return tool_name in self.platform_tools

    def tools_for_role(self, role_name: str) -> list[str]:
        """Every tool a role may call: its own tools plus the platform tools."""
        role = self.roles.get(role_name)
        if role is None:
            return []
        return [*self.platform_tools, *role.tools]

    def badge_ttl_for(self, role_name: str) -> int:
        override = self.roles[role_name].badge_ttl_minutes
        return override if override is not None else self.badge_ttl_minutes


def _normalize_map_specs(raw: dict) -> dict:
    """YAML writes a map's value spec under `values`; ArgSpec reads it as `values_spec`.

    `values` already means "enum members" for enum args, so map specs are rewritten
    before validation to keep the two meanings apart.
    """

    def fix(spec: dict) -> dict:
        if isinstance(spec, dict) and spec.get("type") == "map":
            fixed = dict(spec)
            fixed["values_spec"] = fixed.pop("values")
            return fixed
        return spec

    result = dict(raw)
    result["handoffs"] = {
        channel_id: {
            **channel,
            "schema": {name: fix(spec) for name, spec in channel.get("schema", {}).items()},
        }
        for channel_id, channel in raw.get("handoffs", {}).items()
    }
    return result


def load_config(path: Path | str = DEFAULT_CONFIG_PATH) -> TrialConfig:
    """Read and validate the policy file. Raises on any malformed or inconsistent entry."""
    with open(path, encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    return TrialConfig.model_validate(_normalize_map_specs(raw))
