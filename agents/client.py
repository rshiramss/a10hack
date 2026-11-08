"""HTTP client for the gateway. Scripted and LLM agents both talk through this; it holds
nothing but the badge token and an HTTP connection."""

from __future__ import annotations

import uuid
from typing import Any

import httpx


class GatewayClient:
    def __init__(self, http: httpx.Client, token: str, name: str = "") -> None:
        self._http = http
        self._token = token
        self.name = name

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    def call(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        *,
        key: str | None = None,
        mutating: bool = False,
    ) -> dict[str, Any]:
        """Call one tool. Mutating calls get a fresh idempotency key unless one is given."""
        if mutating and key is None:
            key = str(uuid.uuid4())
        body: dict[str, Any] = {"args": args or {}}
        if key is not None:
            body["idempotency_key"] = key
        response = self._http.post(f"/tools/{tool}", json=body, headers=self._headers())
        return response.json()

    def declare_plan(self, task_id: str, steps: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
        body = {"task_id": task_id, "steps": [{"tool": t, "args": a} for t, a in steps]}
        return self._http.post("/declare_plan", json=body, headers=self._headers()).json()

    def list_my_tools(self) -> dict[str, Any]:
        return self._http.get("/list_my_tools", headers=self._headers()).json()

    def status(self) -> dict[str, Any]:
        return self.call("get_my_status")
