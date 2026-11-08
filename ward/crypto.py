"""Identity layers. Each consult a specialist accepts has passed all of them:

1. Workload credential   client secret, stored only as HMAC-SHA256          (who you are)
2. Badge                 HS256-signed claims, then sealed with AES-256-GCM  (gateway session;
                         (sign-then-encrypt, like a nested JWT). 60 s TTL,   a leaked badge
                         rotated with a new key pair, revocable by jti       reveals nothing)
3. Delegation token      Ed25519 JWT signed by the gateway, audience = one   (only the master,
                         instance, bound to the lease and an args hash        via the gateway)
4. Sealed consult        AES-256-GCM, key derived from the target's current  (only that
                         badge, lease id as associated data                   instance can read)
5. Handshake proof       HMAC over a fresh challenge with the instance key   (the right instance
                                                                              answered)
Keys 2-5 are derived from one master secret with HKDF; the Ed25519 key is generated
fresh at startup and its private half never leaves the gateway.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from typing import Any

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ISSUER = "ward-gateway"
BADGE_PREFIX = "wb1."
BADGE_AAD = b"ward-badge-v1"


def derive(master: bytes, purpose: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=purpose.encode()).derive(
        master
    )


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def hmac_hex(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


def new_secret() -> str:
    return secrets.token_urlsafe(32)


class KeyRing:
    def __init__(self, master: bytes | None = None) -> None:
        self.master = master or os.urandom(32)
        self.badge_key = derive(self.master, "badge")
        self.badge_enc_key = derive(self.master, "badge-encryption")
        self.credential_key = derive(self.master, "credential")
        self._signing = Ed25519PrivateKey.generate()
        self.delegation_public_pem = (
            self._signing.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )

    # 1. credentials
    def credential_hmac(self, secret: str) -> str:
        return hmac_hex(self.credential_key, secret)

    # 2. badges
    def sign_badge(self, claims: dict[str, Any]) -> str:
        """Sign the claims (HS256), then seal the signed token with AES-256-GCM. The result
        is opaque: without the gateway's key nobody can read the agent, role, or key
        thumbprint inside, and any change to it fails the GCM tag."""
        signed = jwt.encode(claims, self.badge_key, algorithm="HS256").encode()
        nonce = os.urandom(12)
        box = AESGCM(self.badge_enc_key).encrypt(nonce, signed, BADGE_AAD)
        return BADGE_PREFIX + base64.urlsafe_b64encode(nonce + box).decode().rstrip("=")

    def read_badge(self, token: str) -> dict[str, Any]:
        """Decrypt, then verify the signature. Expiry, revocation and supersession are
        checked against the database."""
        if not isinstance(token, str) or not token.startswith(BADGE_PREFIX):
            raise jwt.InvalidTokenError("not a ward badge")
        try:
            raw = base64.urlsafe_b64decode(token[len(BADGE_PREFIX) :] + "=" * (-len(token) % 4))
            signed = AESGCM(self.badge_enc_key).decrypt(raw[:12], raw[12:], BADGE_AAD)
        except Exception as exc:  # noqa: BLE001 - any failure to open is an invalid badge
            raise jwt.InvalidTokenError("badge didn't decrypt") from exc
        return jwt.decode(
            signed.decode(),
            self.badge_key,
            algorithms=["HS256"],
            options={"verify_exp": False, "verify_aud": False},
            issuer=ISSUER,
        )

    # 3. delegation tokens
    def sign_delegation(self, claims: dict[str, Any]) -> str:
        return jwt.encode({**claims, "iss": ISSUER}, self._signing, algorithm="EdDSA")

    # 4 + 5. per-instance keys, bound to the instance's current badge
    def instance_keys(self, agent_id: str, badge_jti: str) -> tuple[bytes, bytes]:
        seal = derive(self.master, f"seal:{agent_id}:{badge_jti}")
        proof = derive(self.master, f"proof:{agent_id}:{badge_jti}")
        return seal, proof


def seal(key: bytes, payload: Any, associated: str) -> dict[str, str]:
    nonce = os.urandom(12)
    box = AESGCM(key).encrypt(nonce, canonical(payload), associated.encode())
    return {"nonce": nonce.hex(), "box": box.hex()}


def open_sealed(key: bytes, sealed: dict[str, str], associated: str) -> Any:
    plain = AESGCM(key).decrypt(
        bytes.fromhex(sealed["nonce"]), bytes.fromhex(sealed["box"]), associated.encode()
    )
    return json.loads(plain)


def verify_delegation(public_pem: str, token: str, audience: str) -> dict[str, Any]:
    return jwt.decode(
        token,
        public_pem,
        algorithms=["EdDSA"],
        audience=audience,
        issuer=ISSUER,
        options={"require": ["exp", "aud", "sub", "jti", "lease", "tool", "args_sha256"]},
    )


# ---- 6. proof of possession (DPoP-style) ------------------------------------------------
#
# Each agent generates its own Ed25519 key pair; the private half never leaves the agent.
# Its badge is bound to the public key's thumbprint (cnf.jkt), and every call carries a
# fresh proof signed with the private key: which operation, a hash of the badge, a time,
# and a one-time id. A stolen badge without the key is useless; a captured proof can't be
# replayed.

POP_MAX_SKEW_S = 30


def thumbprint(public_pem: str) -> str:
    return hashlib.sha256(public_pem.encode()).hexdigest()


class AgentKey:
    """An agent's own signing key. Lives only inside the agent."""

    def __init__(self) -> None:
        self._private = Ed25519PrivateKey.generate()
        self.public_pem = (
            self._private.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )
        self.jkt = thumbprint(self.public_pem)

    def proof(self, token: str, op: str) -> str:
        import time
        import uuid

        return jwt.encode(
            {
                "op": op,
                "ath": hashlib.sha256(token.encode()).hexdigest(),
                "iat": int(time.time()),
                "jti": uuid.uuid4().hex,
            },
            self._private,
            algorithm="EdDSA",
        )

    def sign(self, message: str) -> str:
        return self._private.sign(message.encode()).hex()


def verify_proof(public_pem: str, proof: str, token: str, op: str, now_s: float) -> dict[str, Any]:
    """Raises ValueError with a reason code if the proof doesn't hold."""
    try:
        claims = jwt.decode(
            proof,
            public_pem,
            algorithms=["EdDSA"],
            options={"require": ["op", "ath", "iat", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise ValueError("DENY_POP_MISMATCH") from exc
    if claims["ath"] != hashlib.sha256(token.encode()).hexdigest():
        raise ValueError("DENY_POP_MISMATCH")
    if claims["op"] != op:
        raise ValueError("DENY_POP_MISMATCH")
    if abs(now_s - claims["iat"]) > POP_MAX_SKEW_S:
        raise ValueError("DENY_POP_STALE")
    return claims


def verify_signature(public_pem: str, message: str, signature_hex: str) -> bool:
    from cryptography.exceptions import InvalidSignature

    key = serialization.load_pem_public_key(public_pem.encode())
    try:
        key.verify(bytes.fromhex(signature_hex), message.encode())
        return True
    except (InvalidSignature, ValueError):
        return False
