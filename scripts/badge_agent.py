"""Stdio MCP server that Cursor/Claude Code launch. Proxies to Ward's POST /mcp.

Credentials come from an operator-issued file (data/mcp-credentials.env via
WARD_CREDENTIALS_FILE) or WARD_CLIENT_ID / WARD_CLIENT_SECRET. This process
generates its own Ed25519 AgentKey for PoP, attests (SHA-256 of this file),
obtains a badge, rotates every 45s, and signs every request. The calling LLM
never sees the client secret or the badge — and never mints credentials.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx

# When launched as `python scripts/badge_agent.py`, sys.path[0] is scripts/, which
# shadows the `ward/` package with `scripts/ward.py`. Prefer the repo root.
_SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = _SCRIPT_DIR.parent
while str(_SCRIPT_DIR) in sys.path:
    sys.path.remove(str(_SCRIPT_DIR))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ward import crypto  # noqa: E402
from ward.attestation import measure_source_file  # noqa: E402
from ward.env import load_dotenv  # noqa: E402
from ward.mcp import proof_op  # noqa: E402

load_dotenv()

SELF = Path(__file__).resolve()


class BadgeSession:
    def __init__(self, base_url: str, client_id: str, secret: str) -> None:
        self.base = base_url.rstrip("/")
        self.client_id = client_id
        self.secret = secret
        self.key = crypto.AgentKey()
        self.token: str | None = None
        self.expires_ms = 0
        self.issued_ms = 0.0
        self.rotate_after_ms = 45_000
        self._lock = threading.Lock()
        self._http = httpx.Client(timeout=60.0)

    def measurement(self) -> str:
        return measure_source_file(SELF)

    def authenticate(self) -> None:
        body = {
            "client_id": self.client_id,
            "secret": self.secret,
            "public_pem": self.key.public_pem,
            "key_proof": self.key.proof(self.secret, "authenticate"),
            "measurement": self.measurement(),
        }
        r = self._http.post(f"{self.base}/api/agent/token", json=body)
        data = r.json()
        if r.status_code >= 400 or not data.get("ok"):
            reason = data.get("reason", r.status_code)
            detail = data.get("detail", "")
            hint = ""
            if reason in ("DENY_UNKNOWN_AGENT", "DENY_BAD_CREDENTIALS", "DENY_REVOKED"):
                hint = (
                    " — operator must Issue MCP credential in the Ward console "
                    "(writes data/mcp-credentials.env), then reload Cursor MCP"
                )
            raise SystemExit(f"authenticate failed: {reason} {detail}{hint}")
        with self._lock:
            self.token = data["token"]
            self.expires_ms = int(data["expires_ms"])
            self.issued_ms = int(data.get("issued_ms", time.time() * 1000))
            self.rotate_after_ms = int(data.get("rotate_after_ms", 45_000))

    def rotate_if_due(self) -> None:
        with self._lock:
            if not self.token:
                return
            due = (time.time() * 1000 - self.issued_ms) >= self.rotate_after_ms
            token = self.token
            old_key = self.key
        if not due:
            return
        new_key = crypto.AgentKey()
        body = {
            "public_pem": new_key.public_pem,
            "key_proof": new_key.proof(token, "rotate-new-key"),
        }
        r = self._http.post(
            f"{self.base}/api/agent/rotate",
            headers=self._auth_headers("rotate", token, old_key),
            json=body,
        )
        data = r.json()
        if r.status_code >= 400 or not data.get("ok"):
            return
        with self._lock:
            self.key = new_key
            self.token = data["token"]
            self.expires_ms = int(data["expires_ms"])
            self.issued_ms = int(data.get("issued_ms", time.time() * 1000))

    def _auth_headers(
        self, op: str, token: str | None = None, key: crypto.AgentKey | None = None
    ) -> dict[str, str]:
        with self._lock:
            token = token or self.token
            key = key or self.key
        assert token is not None
        return {
            "Authorization": f"Bearer {token}",
            "X-Badge-Proof": key.proof(token, op),
            "Content-Type": "application/json",
        }

    def mcp(self, message: dict[str, Any]) -> dict[str, Any] | None:
        self.rotate_if_due()
        method = str(message.get("method", ""))
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        op = proof_op(method, params)
        with self._lock:
            token = self.token
            key = self.key
        assert token is not None
        r = self._http.post(
            f"{self.base}/mcp",
            headers=self._auth_headers(op, token, key),
            json=message,
        )
        if r.status_code == 202 or not r.content:
            return None
        return r.json()


def read_message() -> dict[str, Any] | None:
    line = sys.stdin.buffer.readline()
    if not line:
        return None
    return json.loads(line.decode())


def write_message(msg: dict[str, Any]) -> None:
    sys.stdout.buffer.write((json.dumps(msg, separators=(",", ":")) + "\n").encode())
    sys.stdout.buffer.flush()


def _load_credentials() -> tuple[str, str]:
    """Prefer an operator-issued credentials file; fall back to env vars.

    The client secret is minted only by Ward's Issue MCP endpoint. This process
    generates its own Ed25519 key pair for proof-of-possession — never the secret.
    """
    path = os.environ.get("WARD_CREDENTIALS_FILE", "").strip()
    if not path:
        default = ROOT / "data" / "mcp-credentials.env"
        if default.is_file():
            path = str(default)
    values: dict[str, str] = {}
    if path and Path(path).is_file():
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip().strip("'").strip('"')
    client_id = os.environ.get("WARD_CLIENT_ID") or values.get("WARD_CLIENT_ID", "")
    secret = os.environ.get("WARD_CLIENT_SECRET") or values.get("WARD_CLIENT_SECRET", "")
    return client_id, secret


def main() -> None:
    base = os.environ.get("WARD_URL", "http://127.0.0.1:8000")
    client_id, secret = _load_credentials()
    if not client_id or not secret:
        print(
            "No credentials. Operator must Issue MCP credential in the Ward console "
            "(writes data/mcp-credentials.env), or set WARD_CLIENT_ID / WARD_CLIENT_SECRET.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    session = BadgeSession(base, client_id, secret)
    session.authenticate()

    def rotator() -> None:
        while True:
            time.sleep(5)
            with contextlib.suppress(Exception):
                session.rotate_if_due()

    threading.Thread(target=rotator, daemon=True).start()

    while True:
        try:
            message = read_message()
        except Exception as exc:  # noqa: BLE001
            write_message(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"parse error: {exc}"},
                }
            )
            continue
        if message is None:
            break
        if not isinstance(message, dict):
            continue
        # Notifications: forward, ignore empty reply.
        if "id" not in message:
            session.mcp(message)
            continue
        reply = session.mcp(message)
        if reply is not None:
            write_message(reply)


if __name__ == "__main__":
    main()
