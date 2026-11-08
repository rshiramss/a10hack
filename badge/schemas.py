"""Input schemas generated from config (pipeline step 8).

Every tool's input model is strict (no type coercion), forbids extra fields, and caps
every string's length. Models are built once per config and cached.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, create_model

from badge import reasons
from badge.config import ArgSpec, TrialConfig
from badge.context import CallContext
from badge.decisions import Allow, Decision, Deny
from badge.models import DeclarePlanArgs


class _ToolInput(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


def _python_type(spec: ArgSpec, default_max_len: int) -> Any:
    if spec.type == "id":
        return Annotated[str, StringConstraints(pattern=spec.pattern, max_length=default_max_len)]
    if spec.type == "enum":
        return Literal[tuple(spec.values)]
    if spec.type == "int":
        return Annotated[int, Field(ge=spec.min, le=spec.max)]
    if spec.type == "text":
        return Annotated[str, StringConstraints(max_length=spec.max_len)]
    if spec.type == "bool":
        return bool
    raise ValueError(f"tool args can't be of type {spec.type!r}")


def _build_model(config: TrialConfig, tool_name: str) -> type[BaseModel]:
    if tool_name == "declare_plan":
        return DeclarePlanArgs
    fields: dict[str, Any] = {}
    for arg_name, spec in config.tool(tool_name).args.items():
        python_type = _python_type(spec, config.default_string_max_len)
        fields[arg_name] = (python_type | None, None) if spec.optional else (python_type, ...)
    return create_model(f"{tool_name}_input", __base__=_ToolInput, **fields)


# Keyed by id(config); the config object is kept in the value so its id can't be reused.
_MODEL_CACHE: dict[int, tuple[TrialConfig, dict[str, type[BaseModel]]]] = {}


def input_models(config: TrialConfig) -> dict[str, type[BaseModel]]:
    cached = _MODEL_CACHE.get(id(config))
    if cached is None or cached[0] is not config:
        cached = (config, {name: _build_model(config, name) for name in config.tools})
        _MODEL_CACHE[id(config)] = cached
    return cached[1]


def validate_input(config: TrialConfig, tool_name: str, args: Any) -> dict[str, Any] | Deny:
    """Validate raw args. Returns the validated dict (omitted optionals dropped) or a Deny."""
    if not isinstance(args, dict):
        return Deny(reasons.DENY_SCHEMA, detail="args must be an object")
    try:
        model = input_models(config)[tool_name].model_validate(args)
    except ValidationError as error:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in item['loc'])}: {item['type']}"
            for item in error.errors()[:5]
        )
        return Deny(reasons.DENY_SCHEMA, detail=problems[:300])
    return model.model_dump(exclude_none=True)


def check_input(ctx: CallContext) -> Decision:
    """Pipeline step 8: strict schema validation of the call's args."""
    validated = validate_input(ctx.config, ctx.request.tool, ctx.request.args)
    if isinstance(validated, Deny):
        return validated
    return Allow({"args": validated})
