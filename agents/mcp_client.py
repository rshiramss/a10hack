"""MCP client for the gateway (Streamable HTTP, JSON responses).

Same interface as `GatewayClient` (call, declare_plan, list_my_tools, status), so the
scripted agents and the LLM runner work over MCP unchanged. Every request carries the
badge as a Bearer token; the gateway's 13 checks apply exactly as on the REST endpoints.
"""

from __future__ import annotations

import itertools
import uuid
from typing import Any

import httpx

from badge.mcp import GATEWAY_META_KEY

PROTOCOL_VERSION = "2025-06-18"


class McpError(RuntimeError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.reason = message


class McpGatewayClient:
    def __init__(self, http: httpx.Client, token: str, name: str = "", path: str = "/mcp") -> None:
        self._http = http
        self._token = token
        self._path = path
        self._ids = itertools.count(1)
        self.name = name

    # ---- JSON-RPC ----------------------------------------------------------------------

    def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        body = {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params or {}}
        response = self._http.post(
            self._path,
            json=body,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": PROTOCOL_VERSION,
            },
        )
        reply = response.json()
        if "error" in reply:
            raise McpError(reply["error"]["code"], reply["error"]["message"])
        return reply["result"]

    def initialize(self) -> dict[str, Any]:
        result = self._rpc(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": self.name or "badge-agent", "version": "0.2.0"},
            },
        )
        self._http.post(
            self._path,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        """MCP tools/list: only the tools the badge's role allows."""
        return self._rpc("tools/list")["tools"]

    def call_tool(
        self, name: str, args: dict[str, Any] | None = None, key: str | None = None
    ) -> dict[str, Any]:
        """MCP tools/call. Returns the gateway decision ({ok, reason, result, ...})."""
        params: dict[str, Any] = {"name": name, "arguments": args or {}}
        if key is not None:
            params["_meta"] = {"idempotency_key": key}
        try:
            result = self._rpc("tools/call", params)
        except McpError as exc:
            return {"ok": False, "reason": exc.reason, "result": None, "detail": str(exc)}
        decision = (result.get("_meta") or {}).get(GATEWAY_META_KEY)
        if isinstance(decision, dict):
            return decision
        return {"ok": not result.get("isError"), "reason": "", "result": result}

    # ---- GatewayClient-compatible surface ------------------------------------------------

    def call(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        *,
        key: str | None = None,
        mutating: bool = False,
    ) -> dict[str, Any]:
        if mutating and key is None:
            key = str(uuid.uuid4())
        return self.call_tool(tool, args, key)

    def declare_plan(self, task_id: str, steps: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
        return self.call_tool(
            "declare_plan",
            {"task_id": task_id, "steps": [{"tool": t, "args": a} for t, a in steps]},
        )

    def list_my_tools(self) -> dict[str, Any]:
        # The raw gateway listing (arg specs, mutating flags), which the LLM runner uses.
        return self.call_tool("list_my_tools")

    def status(self) -> dict[str, Any]:
        return self.call_tool("get_my_status")
