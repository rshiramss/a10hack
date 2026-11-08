"""MCP (Model Context Protocol) front door for the Ward gateway.

Streamable HTTP, JSON responses only. Auth is badge + proof-of-possession:

  Authorization: Bearer <badge>
  X-Badge-Proof: <proof JWT>   op = mcp:<method>  (and :tool for tools/call)

External clients never see specialist tools. The only tool is `ask_ward`, which hands
the prompt to OrchestratorAgent. That master declares plans; the gateway mints leases,
spawns badged specialists, and runs sealed consults. Cursor cannot call get_allergies
(or any specialist tool) even if it tries — that is DENY_ROLE_FORBIDDEN + revoke.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ward.gateway import Badge, Denied, Gateway

SUPPORTED_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
SERVER_INFO = {"name": "ward-gateway", "version": "0.1.0"}
GATEWAY_META_KEY = "dev.ward/decision"

ASK_WARD = "ask_ward"

ASK_WARD_TOOL: dict[str, Any] = {
    "name": ASK_WARD,
    "description": (
        "Send a natural-language hospital request to the Ward gateway. "
        "OrchestratorAgent plans which specialists to consult; every consult goes through "
        "lease → delegation → sealed handshake → typed output. "
        "You cannot call specialist tools (get_allergies, check_coverage, …) yourself."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "prompt": {
                "type": "string",
                "minLength": 1,
                "maxLength": 2000,
                "description": "What to ask the ward (patient id/name, drug, coverage, order, …).",
            }
        },
        "required": ["prompt"],
        "additionalProperties": False,
    },
    "annotations": {"readOnlyHint": False},
}

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
ACCESS_DENIED = -32001


@dataclass(frozen=True)
class McpReply:
    status: int
    body: dict[str, Any] | None  # None -> HTTP 202


def _result(msg_id: Any, result: dict[str, Any]) -> McpReply:
    return McpReply(200, {"jsonrpc": "2.0", "id": msg_id, "result": result})


def _error(msg_id: Any, code: int, message: str, data: Any = None) -> McpReply:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return McpReply(200, {"jsonrpc": "2.0", "id": msg_id, "error": error})


def _tool_result(ok: bool, payload: dict[str, Any], reason: str = "") -> dict[str, Any]:
    if ok:
        text = json.dumps(payload)
    else:
        text = f"{reason}: {payload.get('detail', '')}".strip(": ")
        text += "\n" + json.dumps(payload)
    result: dict[str, Any] = {
        "content": [{"type": "text", "text": text}],
        "isError": not ok,
        "_meta": {GATEWAY_META_KEY: {"ok": ok, "reason": reason, **payload}},
    }
    if isinstance(payload, dict):
        result["structuredContent"] = payload
    return result


def handle_message(
    message: Any,
    gateway: Gateway,
    badge: Badge | None,
    denied: Denied | None,
) -> McpReply:
    """Handle one JSON-RPC message. `badge` is set when front-door PoP succeeded."""
    if isinstance(message, list):
        return _error(None, INVALID_REQUEST, "batch requests are not supported")
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return _error(None, INVALID_REQUEST, "not a JSON-RPC 2.0 message")
    method = message.get("method")
    msg_id = message.get("id")
    params = message.get("params") or {}
    if not isinstance(method, str):
        return McpReply(202, None)
    if "id" not in message:
        return McpReply(202, None)
    if not isinstance(params, dict):
        return _error(msg_id, INVALID_PARAMS, "params must be an object")

    if denied is not None:
        return _error(
            msg_id, ACCESS_DENIED, denied.reason, {"reason": denied.reason, "detail": denied.detail}
        )
    assert badge is not None

    if method == "ping":
        return _result(msg_id, {})

    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[-1]
        try:
            gateway.mcp_touch(badge)
        except Denied as exc:
            return _error(
                msg_id, ACCESS_DENIED, exc.reason, {"reason": exc.reason, "detail": exc.detail}
            )
        return _result(
            msg_id,
            {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
                "instructions": (
                    "Ward hospital gateway. Your only tool is ask_ward. "
                    "Pass the user's request as prompt; OrchestratorAgent consults specialists "
                    "through the gateway. Do not invent or call specialist tool names."
                ),
            },
        )

    if method == "tools/list":
        try:
            gateway.mcp_touch(badge)
            return _result(msg_id, {"tools": gateway.mcp_list_tools_as(badge)})
        except Denied as exc:
            return _error(
                msg_id, ACCESS_DENIED, exc.reason, {"reason": exc.reason, "detail": exc.detail}
            )

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(name, str):
            return _error(msg_id, INVALID_PARAMS, "tools/call needs a tool name")
        try:
            delivered = gateway.mcp_call_tool_as(badge, name, args)
            result = delivered.get("result", delivered)
            return _result(msg_id, _tool_result(True, result if isinstance(result, dict) else {}))
        except Denied as exc:
            payload = {"reason": exc.reason, "detail": exc.detail}
            return _result(msg_id, _tool_result(False, payload, reason=exc.reason))

    return _error(msg_id, METHOD_NOT_FOUND, f"method {method} not supported")


def proof_op(method: str, params: dict[str, Any] | None = None) -> str:
    """PoP operation string the badge agent must sign for this MCP method."""
    params = params or {}
    if method == "tools/call":
        name = params.get("name") if isinstance(params, dict) else None
        return f"mcp:tools/call:{name}" if isinstance(name, str) else "mcp:tools/call"
    if method.startswith("notifications/"):
        return f"mcp:{method}"
    return f"mcp:{method}"
