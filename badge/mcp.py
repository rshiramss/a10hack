"""MCP (Model Context Protocol) front door for the gateway. No FastAPI imports.

Any MCP client (Claude Code, Cursor, the MCP Inspector, our own agents) connects to
POST /mcp with its badge as `Authorization: Bearer <badge>`. Then:

  initialize   the badge must verify (signature, expiry, revocation, agent active)
  tools/list   only the badge role's tools: an assessor never sees get_assignment.
               Goes through the pipeline as list_my_tools, so it is audited.
  tools/call   goes through `handle_call` exactly like POST /tools/{name}: same 13
               checks, same audit, same revocation. A denial comes back as an MCP tool
               error carrying the reason code (e.g. DENY_REVOKED).

Stateless JSON responses only (the Streamable HTTP transport allows a server to answer a
POST with plain application/json). No server-initiated messages, no sessions.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from badge import tool_schemas

SUPPORTED_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
SERVER_INFO = {"name": "badge-gateway", "version": "0.2.0"}
# Already exposed by tools/list itself.
HIDDEN_TOOLS = {"list_my_tools"}
# The full gateway decision rides along in each tools/call result's _meta.
GATEWAY_META_KEY = "dev.badge/decision"

# JSON-RPC error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
ACCESS_DENIED = -32001

# run_call(tool, args, idempotency_key) -> {"ok": bool, "reason": str, "result"?: ..., ...}
RunCall = Callable[[str, Any, str | None], dict[str, Any]]
# check_badge() -> None if the badge is good, else a deny reason code
CheckBadge = Callable[[], str | None]


@dataclass(frozen=True)
class McpReply:
    status: int  # HTTP status
    body: dict[str, Any] | None  # None -> 202 with no body (notifications)


def _result(msg_id: Any, result: dict[str, Any]) -> McpReply:
    return McpReply(200, {"jsonrpc": "2.0", "id": msg_id, "result": result})


def _error(msg_id: Any, code: int, message: str, data: Any = None) -> McpReply:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return McpReply(200, {"jsonrpc": "2.0", "id": msg_id, "error": error})


def to_mcp_tools(listing: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": tool["name"],
            "description": tool_schemas.description(tool),
            "inputSchema": tool_schemas.input_schema(tool),
            "annotations": {"readOnlyHint": not tool.get("mutating", False)},
        }
        for tool in listing
        if tool["name"] not in HIDDEN_TOOLS
    ]


def _tool_result(response: dict[str, Any]) -> dict[str, Any]:
    ok = bool(response.get("ok"))
    if ok:
        payload = response.get("result", {})
        text = json.dumps(payload)
    else:
        payload = {k: v for k, v in response.items() if k != "ok"}
        text = f"{response.get('reason', 'DENY')}: {response.get('detail', '')}".strip(": ")
        text += "\n" + json.dumps(payload)
    result: dict[str, Any] = {
        "content": [{"type": "text", "text": text}],
        "isError": not ok,
        "_meta": {GATEWAY_META_KEY: response},
    }
    if isinstance(payload, dict):
        result["structuredContent"] = payload
    return result


def handle_message(
    message: Any, check_badge: CheckBadge, run_call: RunCall, mutating_tools: set[str]
) -> McpReply:
    """Handle one JSON-RPC message from an MCP client."""
    if isinstance(message, list):
        return _error(None, INVALID_REQUEST, "batch requests are not supported")
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return _error(None, INVALID_REQUEST, "not a JSON-RPC 2.0 message")
    method = message.get("method")
    msg_id = message.get("id")
    params = message.get("params") or {}
    if not isinstance(method, str):
        # A response from the client to a server request. We never send any.
        return McpReply(202, None)
    if "id" not in message:  # notification (e.g. notifications/initialized)
        return McpReply(202, None)
    if not isinstance(params, dict):
        return _error(msg_id, INVALID_PARAMS, "params must be an object")

    if method == "ping":
        return _result(msg_id, {})

    if method == "initialize":
        # Connecting needs a valid badge. tools/* are checked (and audited) by the pipeline.
        denied = check_badge()
        if denied is not None:
            return _error(msg_id, ACCESS_DENIED, denied, {"reason": denied})
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[-1]
        return _result(
            msg_id,
            {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
                "instructions": (
                    "Badge gateway. Call get_my_status, then declare_plan with every step, "
                    "then run exactly those steps. Off-plan or out-of-role calls are denied "
                    "and can revoke your badge."
                ),
            },
        )

    if method == "tools/list":
        response = run_call("list_my_tools", {}, None)
        if not response.get("ok"):
            reason = str(response.get("reason", "DENY"))
            return _error(msg_id, ACCESS_DENIED, reason, {"reason": reason})
        return _result(msg_id, {"tools": to_mcp_tools(response["result"]["tools"])})

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(name, str):
            return _error(msg_id, INVALID_PARAMS, "tools/call needs a tool name")
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        key = meta.get("idempotency_key")
        if not isinstance(key, str):
            # MCP has no idempotency field; clients may pass one in _meta to get replay
            # protection. Otherwise each call gets a fresh key.
            key = str(uuid.uuid4())
        if name not in mutating_tools:
            key = None
        # Unknown and hidden tool names still go to the pipeline: calling a tool outside
        # the role is exactly what the role check exists to catch (and revoke).
        return _result(msg_id, _tool_result(run_call(name, args, key)))

    return _error(msg_id, METHOD_NOT_FOUND, f"method {method} not supported")
