"""Load and validate config/hospital.yaml. A bad policy file fails at startup, not mid-demo."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config" / "hospital.yaml"
TYPES = {"id", "enum", "int", "bool", "list"}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class FieldSpec:
    type: str
    pattern: str | None = None
    values: tuple[str, ...] = ()
    min: int | None = None
    max: int | None = None
    items: FieldSpec | None = None
    max_items: int | None = None

    def describe(self) -> str:
        """Short human/LLM description, e.g. 'one of: a, b' or 'int 1..10'."""
        if self.type == "enum":
            return "one of: " + ", ".join(self.values)
        if self.type == "int":
            return f"integer {self.min}..{self.max}"
        if self.type == "id":
            return f"id matching {self.pattern}"
        if self.type == "list" and self.items:
            return f"list of ({self.items.describe()})"
        return self.type


@dataclass(frozen=True)
class InputSpec:
    name: str
    source_tool: str
    source_field: str
    required: bool


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    owner: str
    args: dict[str, FieldSpec]
    output: dict[str, FieldSpec]
    inputs: tuple[InputSpec, ...] = ()
    mutating: bool = False


@dataclass(frozen=True)
class RoleSpec:
    name: str
    display_name: str
    description: str
    master: bool = False
    external: bool = False
    may_delegate: bool = False
    tools: tuple[str, ...] = ()
    tools_allowed: tuple[str, ...] | None = None  # None = N/A; ("*",) = all tools
    callable_by: tuple[str, ...] = ()

    def allows_tool(self, tool: str) -> bool:
        """Whether this role may request `tool` via a plan / MCP call."""
        if self.master:
            return True  # master plans; ownership is checked on the target specialist
        if self.tools_allowed is None:
            return tool in self.tools
        if self.tools_allowed == ("*",):
            return True
        return tool in self.tools_allowed


@dataclass(frozen=True)
class WardConfig:
    system_id: str
    badge_ttl_seconds: int
    delegation_ttl_seconds: int
    run: dict[str, Any]
    revoke_on_pop_failure: bool
    rotate_after_seconds: int
    roles: dict[str, RoleSpec]
    tools: dict[str, ToolSpec]
    vocab: dict[str, tuple[str, ...]]
    allergy_blocks: dict[str, tuple[str, ...]]
    injection_patterns: tuple[re.Pattern[str], ...] = field(default=())
    master: dict[str, Any] = field(default_factory=dict)

    @property
    def master_role(self) -> str:
        return next(name for name, role in self.roles.items() if role.master)

    def specialists(self) -> list[RoleSpec]:
        return [role for role in self.roles.values() if not role.master and not role.external]

    def external_roles(self) -> list[RoleSpec]:
        return [role for role in self.roles.values() if role.external]

    def role_for_display(self, display_name: str) -> str | None:
        for name, role in self.roles.items():
            if display_name in (role.display_name, name):
                return name
        return None

    def owner_role(self, tool: str) -> str | None:
        spec = self.tools.get(tool)
        return spec.owner if spec else None


def _field(raw: Any, vocab: dict[str, tuple[str, ...]], where: str) -> FieldSpec:
    if not isinstance(raw, dict) or raw.get("type") not in TYPES:
        raise ConfigError(f"{where}: bad field spec {raw!r}")
    kind = raw["type"]
    if kind == "enum":
        if "vocab" in raw:
            if raw["vocab"] not in vocab:
                raise ConfigError(f"{where}: unknown vocab {raw['vocab']!r}")
            values = vocab[raw["vocab"]]
        else:
            values = tuple(raw.get("values", ()))
        if not values:
            raise ConfigError(f"{where}: enum without values")
        return FieldSpec(type=kind, values=tuple(values))
    if kind == "int":
        return FieldSpec(type=kind, min=int(raw["min"]), max=int(raw["max"]))
    if kind == "id":
        re.compile(raw["pattern"])
        return FieldSpec(type=kind, pattern=raw["pattern"])
    if kind == "list":
        return FieldSpec(
            type=kind,
            items=_field(raw["items"], vocab, f"{where}.items"),
            max_items=int(raw.get("max_items", 16)),
        )
    return FieldSpec(type=kind)


def load_config(path: Path | str = DEFAULT_PATH) -> WardConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    vocab = {name: tuple(values) for name, values in raw["vocab"].items()}

    roles: dict[str, RoleSpec] = {}
    owner_of: dict[str, str] = {}
    for name, spec in raw["roles"].items():
        allowed_raw = spec.get("tools_allowed")
        if allowed_raw == "*":
            tools_allowed: tuple[str, ...] | None = ("*",)
        elif allowed_raw is None:
            tools_allowed = None
        else:
            tools_allowed = tuple(allowed_raw)
        role = RoleSpec(
            name=name,
            display_name=spec["display_name"],
            description=spec.get("description", ""),
            master=bool(spec.get("master", False)),
            external=bool(spec.get("external", False)),
            may_delegate=bool(spec.get("may_delegate", False)),
            tools=tuple(spec.get("tools", ())),
            tools_allowed=tools_allowed,
            callable_by=tuple(spec.get("callable_by", ())),
        )
        roles[name] = role
        for tool in role.tools:
            if tool in owner_of:
                raise ConfigError(f"tool {tool} owned by both {owner_of[tool]} and {name}")
            owner_of[tool] = name
    masters = [r for r in roles.values() if r.master]
    if len(masters) != 1:
        raise ConfigError("exactly one role must be master: true")
    if masters[0].tools:
        raise ConfigError("the master role owns no tools; it only delegates")
    if masters[0].external:
        raise ConfigError("the master role cannot be external")
    for role in roles.values():
        if role.external:
            if role.tools:
                raise ConfigError(f"external role {role.name} owns no tools; use tools_allowed")
            if not role.may_delegate:
                raise ConfigError(f"external role {role.name} must set may_delegate: true")
            if role.tools_allowed is None:
                raise ConfigError(f"external role {role.name} needs tools_allowed")
            if role.tools_allowed != ("*",):
                for tool in role.tools_allowed:
                    if tool not in owner_of:
                        raise ConfigError(f"{role.name}.tools_allowed names unknown tool {tool}")
        elif role.may_delegate and not role.master:
            raise ConfigError(f"{role.name}: may_delegate is only for master/external roles")
        for caller in role.callable_by:
            if caller not in roles:
                raise ConfigError(f"{role.name}.callable_by names unknown role {caller}")

    tools: dict[str, ToolSpec] = {}
    for name, spec in raw["tools"].items():
        if name not in owner_of:
            raise ConfigError(f"tool {name} has no owning role")
        args = {a: _field(s, vocab, f"{name}.args.{a}") for a, s in spec.get("args", {}).items()}
        output = {f: _field(s, vocab, f"{name}.output.{f}") for f, s in spec["output"].items()}
        inputs = tuple(
            InputSpec(i, s["from"], s["field"], bool(s.get("required", True)))
            for i, s in spec.get("inputs", {}).items()
        )
        tools[name] = ToolSpec(
            name=name,
            description=spec["description"],
            owner=owner_of[name],
            args=args,
            output=output,
            inputs=inputs,
            mutating=bool(spec.get("mutating", False)),
        )
    for role in roles.values():
        for tool in role.tools:
            if tool not in tools:
                raise ConfigError(f"role {role.name} lists unknown tool {tool}")
    for tool in tools.values():
        for item in tool.inputs:
            source = tools.get(item.source_tool)
            if source is None or item.source_field not in source.output:
                raise ConfigError(
                    f"{tool.name}.inputs.{item.name}: {item.source_tool}.{item.source_field}"
                    " doesn't exist"
                )

    run = dict(raw["run"])
    return WardConfig(
        system_id=raw["system_id"],
        badge_ttl_seconds=int(raw["identity"]["badge_ttl_seconds"]),
        delegation_ttl_seconds=int(raw["identity"]["delegation_ttl_seconds"]),
        revoke_on_pop_failure=bool(raw["identity"].get("revoke_on_pop_failure", True)),
        rotate_after_seconds=int(raw["identity"].get("rotate_after_seconds", 45)),
        run=run,
        roles=roles,
        tools=tools,
        vocab=vocab,
        allergy_blocks={k: tuple(v) for k, v in raw.get("allergy_blocks", {}).items()},
        master=dict(raw.get("master", {})),
        injection_patterns=tuple(
            re.compile(p, re.MULTILINE) for p in raw["scanners"]["injection_patterns"]
        ),
    )
