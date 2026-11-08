"""A specialist agent instance (PharmacyAgent2, LabsAgent1, ...).

It holds its own workload secret and badge, and does exactly one kind of thing: accept a
consult offer from the gateway, verify it, run one atomic tool, and seal the typed result.
It has no way to address another agent and never sees natural language from one.

The instance refuses an offer unless:
  - the delegation token verifies against the gateway's Ed25519 public key,
  - the token's audience is this exact instance and its subject is a master agent,
  - the sealed request opens with this instance's key (bound to its current badge),
  - the request's tool is one this role owns and its args hash matches the token.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

import jwt

from ward import crypto
from ward.attestation import measure
from ward.config import WardConfig
from ward.tools import TOOLS


class OfferRefused(Exception):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass
class Session:
    badge: str
    badge_jti: str
    seal_key: bytes
    proof_key: bytes


class SpecialistInstance:
    def __init__(
        self,
        agent_id: str,
        role: str,
        client_secret: str,
        config: WardConfig,
        gateway_public_pem: str,
        master_role: str,
        functions: dict[str, Any] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.role = role
        self._secret = client_secret
        self._config = config
        self._gateway_public_pem = gateway_public_pem
        self._master_role = master_role
        self.session: Session | None = None
        # The instance's own key pair; the private half never leaves this object.
        self.key = crypto.AgentKey()
        # The code this instance would run. Attestation hashes exactly this.
        self._functions = functions or {t: TOOLS[t] for t in config.roles[role].tools}

    def measurement(self) -> str:
        return measure(self.role, self._config, self._functions)

    def login(self, gateway: Any) -> None:
        """Present secret + public key (with proof of possession) + code measurement."""
        session = gateway.authenticate(
            self.agent_id,
            self._secret,
            self.key.public_pem,
            self.key.proof(self._secret, "authenticate"),
            self.measurement(),
        )
        self.adopt_session(
            session["token"], session["jti"], session["seal_key"], session["proof_key"]
        )

    @property
    def client_secret(self) -> str:
        return self._secret

    def adopt_session(self, badge: str, badge_jti: str, seal_key: bytes, proof_key: bytes) -> None:
        self.session = Session(badge, badge_jti, seal_key, proof_key)

    def rotate(self, gateway: Any) -> None:
        """New key pair; prove old + new key; adopt the new badge. The old one dies."""
        assert self.session is not None
        from ward.gateway import Credential

        new_key = crypto.AgentKey()
        token = self.session.badge
        session = gateway.rotate(
            Credential(token, self.key.proof(token, "rotate")),
            new_key.public_pem,
            new_key.proof(token, "rotate-new-key"),
        )
        self.key = new_key
        self.adopt_session(
            session["token"], session["jti"], session["seal_key"], session["proof_key"]
        )

    def handle_offer(self, offer: dict[str, Any], challenge: str) -> dict[str, Any]:
        """Verify an offer and answer the handshake. Raises OfferRefused."""
        if self.session is None:
            raise OfferRefused("DENY_NOT_AUTHENTICATED", "instance has no badge")
        try:
            claims = crypto.verify_delegation(
                self._gateway_public_pem, offer["delegation"], audience=self.agent_id
            )
        except jwt.PyJWTError as exc:
            raise OfferRefused("DENY_BAD_DELEGATION", type(exc).__name__) from exc
        if claims.get("sub_role") != self._master_role:
            raise OfferRefused("DENY_NOT_MASTER", "only the master agent may delegate")
        try:
            request = crypto.open_sealed(self.session.seal_key, offer["sealed"], claims["lease"])
        except Exception as exc:  # noqa: BLE001 - any failure to open is a refusal
            raise OfferRefused("DENY_SEAL", "request didn't open with this instance's key") from exc
        if request.get("tool") != claims["tool"]:
            raise OfferRefused("DENY_BAD_DELEGATION", "tool doesn't match the token")
        if crypto.sha256_hex(request.get("args")) != claims["args_sha256"]:
            raise OfferRefused("DENY_BAD_DELEGATION", "args don't match the token")
        if request["tool"] not in self._config.roles[self.role].tools:
            raise OfferRefused("DENY_ROLE_FORBIDDEN", f"{self.role} doesn't own {request['tool']}")
        proof = crypto.hmac_hex(self.session.proof_key, f"{challenge}:{claims['lease']}")
        pop = self.key.sign(f"{challenge}:{claims['lease']}")
        return {
            "accept": True,
            "proof": proof,
            "pop": pop,
            "badge": self.session.badge,
            "request": request,
        }

    def run_tool(self, conn: sqlite3.Connection, request: dict[str, Any], lease_id: str) -> dict:
        """Run the atomic function and seal its typed result back to the gateway."""
        assert self.session is not None
        function = self._functions[request["tool"]]
        output = function(conn, self._config, request["args"], request["inputs"])
        return crypto.seal(self.session.seal_key, output, f"result:{lease_id}")
