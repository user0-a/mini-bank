"""WWGateWaySolution Python SDK — single file, vendorable.

Two roles:

* ``AgentClient``     — used by AI agents: signs requests to the gateway and creates
                        proof-of-possession headers when calling bank systems.
* ``GatewayVerifier`` — used by bank systems: verifies action/data tokens LOCALLY
                        (EdDSA signature via JWKS), checks audience, action, parameters,
                        plan binding, proof of possession, single use, revocation and the
                        live risk policy. Fails closed when policy data is stale.

Dependencies: ``cryptography`` and ``httpx``. Canonicalization follows the JCS profile documented
in docs/PROTOCOL.md; it must stay byte-identical with the gateway and the Java verifier.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import secrets
import sqlite3
import threading
import time
from decimal import Decimal
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

__version__ = "0.2.0"

TYP_ACTION = "wwg-action+jwt"
TYP_DATA = "wwg-data+jwt"
TYP_POLICY = "wwg-policy+jwt"
TYP_PROOF = "wwg-proof+jwt"
RISK_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# --------------------------------------------------------------------------- canonical JSON (JCS)


def _format_float(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("NaN/Infinity cannot be canonicalized")
    if value == 0:
        return "0"
    if value.is_integer() and abs(value) < 1e21:
        return str(int(value))
    sign = "-" if value < 0 else ""
    _, digits_tuple, exponent = Decimal(repr(abs(value))).as_tuple()
    all_digits = "".join(str(d) for d in digits_tuple)
    digits = all_digits.rstrip("0") or "0"
    n = len(all_digits) + exponent
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        out = digits[0] + ("." + digits[1:] if k > 1 else "") + f"e{'+' if e > 0 else '-'}{abs(e)}"
    return sign + out


def _ser(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        out.append(str(value))
    elif isinstance(value, float):
        out.append(_format_float(value))
    elif isinstance(value, str):
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _ser(item, out)
        out.append("]")
    elif isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise ValueError("object keys must be strings")
        out.append("{")
        for i, key in enumerate(sorted(value, key=lambda k: k.encode("utf-16-be"))):
            if i:
                out.append(",")
            out.append(json.dumps(key, ensure_ascii=False))
            out.append(":")
            _ser(value[key], out)
        out.append("}")
    else:
        raise ValueError(f"unsupported type: {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    out: list[str] = []
    _ser(value, out)
    return "".join(out).encode("utf-8")


def params_hash(params: Any) -> str:
    return hashlib.sha256(canonicalize(params)).hexdigest()


# --------------------------------------------------------------------------- base64url / JWK / JWS


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(value: str) -> bytes:
    if not isinstance(value, str) or any(c in value for c in "+/="):
        raise VerificationError("malformed_token", "invalid base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise VerificationError("malformed_token", "invalid base64url") from exc


def public_jwk(key: Ed25519PublicKey) -> dict[str, str]:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}


def jwk_to_key(jwk: Any) -> Ed25519PublicKey:
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise VerificationError("bad_key", "unsupported key type")
    raw = unb64url(jwk.get("x", ""))
    if len(raw) != 32:
        raise VerificationError("bad_key", "invalid Ed25519 key")
    return Ed25519PublicKey.from_public_bytes(raw)


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    return b64url(hashlib.sha256(canonicalize({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]})).digest())


def sign_jws(key: Ed25519PrivateKey, header: dict[str, Any], payload: dict[str, Any]) -> str:
    signing_input = b64url(canonicalize({**header, "alg": "EdDSA"})) + "." + b64url(canonicalize(payload))
    return signing_input + "." + b64url(key.sign(signing_input.encode("ascii")))


def _decode(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    if not isinstance(token, str) or token.count(".") != 2 or len(token) > 16384:
        raise VerificationError("malformed_token", "malformed token")
    h, p, s = token.split(".")
    try:
        header = json.loads(unb64url(h))
        payload = json.loads(unb64url(p))
    except (ValueError, UnicodeDecodeError) as exc:
        raise VerificationError("malformed_token", "malformed token") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise VerificationError("malformed_token", "malformed token")
    return header, payload, f"{h}.{p}".encode("ascii"), unb64url(s)


def _verify_sig(key: Ed25519PublicKey, signing_input: bytes, signature: bytes) -> None:
    try:
        key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise VerificationError("bad_signature", "signature verification failed") from exc


# --------------------------------------------------------------------------- errors / replay stores


class VerificationError(Exception):
    """code is stable and machine-readable; status is the HTTP status a server should return."""

    def __init__(self, code: str, message: str, status: int = 401) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


class ReplayStore(Protocol):
    def add(self, key: str, expires_at: int) -> bool:
        """Atomically record key; return False if it already exists (= replay)."""


class MemoryReplayStore:
    def __init__(self) -> None:
        self._data: dict[str, int] = {}
        self._lock = threading.Lock()

    def add(self, key: str, expires_at: int) -> bool:
        now = int(time.time())
        with self._lock:
            if len(self._data) > 10000:
                self._data = {k: v for k, v in self._data.items() if v > now}
            if key in self._data and self._data[key] > now:
                return False
            self._data[key] = expires_at
            return True


class SQLiteReplayStore:
    """Durable, atomic single-use store (PRIMARY KEY) — survives restarts of the bank service."""

    def __init__(self, path: str) -> None:
        self.path = path
        with self._conn() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS wwg_replay (key TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)")

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)

    def add(self, key: str, expires_at: int) -> bool:
        now = int(time.time())
        with self._conn() as conn:
            conn.execute("DELETE FROM wwg_replay WHERE expires_at < ?", (now,))
            cur = conn.execute("INSERT OR IGNORE INTO wwg_replay (key, expires_at) VALUES (?, ?)", (key, expires_at))
            return cur.rowcount == 1


# --------------------------------------------------------------------------- agent side


class AgentClient:
    """Signs gateway requests and creates proofs of possession for bank calls."""

    def __init__(self, agent_id: str, private_key: Ed25519PrivateKey, gateway_url: str = "http://127.0.0.1:8001") -> None:
        self.agent_id = agent_id
        self.key = private_key
        self.gateway_url = gateway_url.rstrip("/")
        self.jwk = public_jwk(private_key.public_key())

    @staticmethod
    def generate_key() -> Ed25519PrivateKey:
        return Ed25519PrivateKey.generate()

    @staticmethod
    def load_key(pem: bytes) -> Ed25519PrivateKey:
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("agent key must be Ed25519")
        return key

    @staticmethod
    def dump_key(key: Ed25519PrivateKey) -> bytes:
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    def signed_headers(self, method: str, path: str, body: bytes, prefix: str = "x-agent") -> dict[str, str]:
        ts = int(time.time())
        nonce = secrets.token_urlsafe(16)
        payload = canonicalize({"m": method.upper(), "p": path, "ts": ts, "n": nonce, "bh": b64url(hashlib.sha256(body).digest())})
        return {
            f"{prefix}-id": self.agent_id,
            f"{prefix}-timestamp": str(ts),
            f"{prefix}-nonce": nonce,
            f"{prefix}-signature": b64url(self.key.sign(payload)),
        }

    def proof(self, method: str, url: str, token: str) -> str:
        payload = {
            "htm": method.upper(),
            "htu": url,
            "iat": int(time.time()),
            "jti": secrets.token_urlsafe(16),
            "ath": b64url(hashlib.sha256(token.encode("ascii")).digest()),
        }
        return sign_jws(self.key, {"typ": TYP_PROOF, "jwk": self.jwk}, payload)


# --------------------------------------------------------------------------- bank side


class GatewayVerifier:
    """Local verification of WWGateWay tokens inside a bank system.

    Network access to the gateway is needed only for the JWKS (cached, refreshed on unknown kid)
    and the signed policy snapshot (revocations + live risk tolerance, cached for a few seconds).
    If the snapshot cannot be refreshed within ``snapshot_max_age`` seconds, every request fails
    closed with ``policy_unavailable``.
    """

    def __init__(
        self,
        *,
        gateway_url: str,
        issuer: str,
        audience: str,
        replay_store: ReplayStore | None = None,
        require_pop: bool = True,
        clock_skew: int = 5,
        proof_max_age: int = 60,
        snapshot_max_age: int = 30,
        fetch_json: Callable[[str], dict[str, Any]] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.gateway_url = gateway_url.rstrip("/")
        self.issuer = issuer
        self.audience = audience
        self.replay = replay_store or MemoryReplayStore()
        self.require_pop = require_pop
        self.skew = clock_skew
        self.proof_max_age = proof_max_age
        self.snapshot_max_age = snapshot_max_age
        self.clock = clock
        self._fetch = fetch_json or self._http_fetch
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._keys_fetched_at = 0.0
        self._snapshot: dict[str, Any] | None = None
        self._lock = threading.RLock()

    # -- network
    @staticmethod
    def _http_fetch(url: str) -> dict[str, Any]:
        import httpx

        response = httpx.get(url, timeout=3)
        response.raise_for_status()
        return response.json()

    def _refresh_keys(self) -> None:
        jwks = self._fetch(f"{self.gateway_url}/.well-known/jwks.json")
        keys = {}
        for jwk in jwks.get("keys", []):
            if jwk.get("alg", "EdDSA") == "EdDSA" and isinstance(jwk.get("kid"), str):
                keys[jwk["kid"]] = jwk_to_key(jwk)
        self._keys = keys
        self._keys_fetched_at = self.clock()

    def _key(self, kid: Any) -> Ed25519PublicKey:
        with self._lock:
            if not isinstance(kid, str):
                raise VerificationError("unknown_kid", "missing kid")
            if kid not in self._keys and self.clock() - self._keys_fetched_at > 10:
                try:
                    self._refresh_keys()
                except Exception as exc:
                    raise VerificationError("keys_unavailable", f"cannot fetch gateway keys: {exc}", 503) from exc
            if kid not in self._keys:
                raise VerificationError("unknown_kid", "token signed with an unknown key")
            return self._keys[kid]

    def policy(self) -> dict[str, Any]:
        with self._lock:
            now = self.clock()
            snap = self._snapshot
            if snap is not None and now < snap["exp"] and now - snap["iat"] <= self.snapshot_max_age:
                return snap
            try:
                token = self._fetch(f"{self.gateway_url}/v1/policy-snapshot")["snapshot"]
                header, payload, signing_input, sig = _decode(token)
                if header.get("alg") != "EdDSA" or header.get("typ") != TYP_POLICY:
                    raise VerificationError("bad_policy", "unexpected policy snapshot type")
                _verify_sig(self._key(header.get("kid")), signing_input, sig)
                if payload.get("iss") != self.issuer:
                    raise VerificationError("bad_policy", "policy snapshot from wrong issuer")
                if snap is not None and payload.get("iat", 0) < snap["iat"]:
                    raise VerificationError("bad_policy", "policy snapshot rollback")
                iat, exp = payload.get("iat"), payload.get("exp")
                if not isinstance(iat, int) or not isinstance(exp, int) or now - iat > self.snapshot_max_age or iat - now > self.skew or now >= exp + self.skew:
                    raise VerificationError("policy_unavailable", "policy snapshot is not fresh (replayed or clock skew)", 503)
                self._snapshot = payload
                return payload
            except VerificationError:
                raise
            except Exception as exc:
                if snap is not None and now - snap["iat"] <= self.snapshot_max_age:
                    return snap
                raise VerificationError("policy_unavailable", f"gateway policy unavailable: {exc}", 503) from exc

    # -- shared checks
    def _verify_token(self, token: str, typ: str) -> dict[str, Any]:
        header, payload, signing_input, sig = _decode(token)
        if header.get("alg") != "EdDSA":
            raise VerificationError("bad_alg", "only EdDSA tokens are accepted")
        if header.get("typ") != typ:
            raise VerificationError("wrong_token_type", f"expected {typ}")
        if "crit" in header:
            raise VerificationError("bad_header", "unsupported critical header")
        _verify_sig(self._key(header.get("kid")), signing_input, sig)
        now = self.clock()
        if payload.get("iss") != self.issuer:
            raise VerificationError("wrong_issuer", "token issued by an untrusted issuer")
        if payload.get("aud") != self.audience:
            raise VerificationError("wrong_audience", "token is not intended for this system", 403)
        exp, nbf = payload.get("exp"), payload.get("nbf", payload.get("iat"))
        if not isinstance(exp, int) or now >= exp + self.skew:
            raise VerificationError("expired", "token expired")
        if not isinstance(nbf, int) or now + self.skew < nbf:
            raise VerificationError("not_yet_valid", "token not yet valid")
        if not isinstance(payload.get("jti"), str):
            raise VerificationError("malformed_token", "missing jti")
        return payload

    def _check_policy(self, claims: dict[str, Any]) -> None:
        snap = self.policy()
        if claims["jti"] in set(snap.get("revoked_jti", [])):
            raise VerificationError("revoked", "token revoked")
        if claims.get("sub") in set(snap.get("revoked_agents", [])):
            raise VerificationError("agent_revoked", "agent suspended")
        if claims.get("plan_id") and claims["plan_id"] in set(snap.get("revoked_plans", [])):
            raise VerificationError("plan_revoked", "plan cancelled")
        global_tol = snap.get("risk_tolerance", "low")
        system_tol = (snap.get("system_risk_tolerances") or {}).get(self.audience)
        tol = global_tol
        if system_tol in RISK_ORDER and RISK_ORDER[system_tol] < RISK_ORDER.get(global_tol, 1):
            tol = system_tol
        risk = claims.get("risk_level")
        if risk not in RISK_ORDER or RISK_ORDER[risk] > RISK_ORDER.get(tol, 1):
            raise VerificationError("risk_tolerance", f"token risk {risk} exceeds current tolerance {tol}")

    def _check_proof(self, claims: dict[str, Any], token: str, proof: str | None, method: str, url: str) -> None:
        jkt = (claims.get("cnf") or {}).get("jkt")
        if not jkt:
            if self.require_pop:
                raise VerificationError("pop_required", "token is not bound to an agent key")
            return
        if not proof:
            raise VerificationError("proof_missing", "proof of possession required")
        header, payload, signing_input, sig = _decode(proof)
        if header.get("alg") != "EdDSA" or header.get("typ") != TYP_PROOF:
            raise VerificationError("bad_proof", "invalid proof header")
        jwk = header.get("jwk")
        key = jwk_to_key(jwk)
        if jwk_thumbprint(jwk) != jkt:
            raise VerificationError("proof_key_mismatch", "proof not signed by the key bound to the token")
        _verify_sig(key, signing_input, sig)
        if payload.get("htm") != method.upper():
            raise VerificationError("proof_method_mismatch", "proof issued for another HTTP method")
        if urlsplit(str(payload.get("htu", ""))).path != urlsplit(url).path:
            raise VerificationError("proof_url_mismatch", "proof issued for another URL")
        if payload.get("ath") != b64url(hashlib.sha256(token.encode("ascii")).digest()):
            raise VerificationError("proof_token_mismatch", "proof issued for another token")
        iat, now = payload.get("iat"), self.clock()
        if not isinstance(iat, int) or abs(now - iat) > self.proof_max_age:
            raise VerificationError("proof_stale", "proof is too old or from the future")
        jti = payload.get("jti")
        if not isinstance(jti, str) or not self.replay.add(f"proof:{jkt}:{jti}", int(now) + self.proof_max_age + self.skew):
            raise VerificationError("proof_replay", "proof already used")

    # -- public API
    def verify_action(self, token: str, proof: str | None, *, method: str, url: str, action: str, params: Any, consume: bool = True) -> dict[str, Any]:
        claims = self._verify_token(token, TYP_ACTION)
        if claims.get("action") != action:
            raise VerificationError("wrong_action", "token authorizes a different action", 403)
        if claims.get("params_hash") != params_hash(params):
            raise VerificationError("params_mismatch", "request parameters differ from the authorized ones", 403)
        self._check_policy(claims)
        self._check_proof(claims, token, proof, method, url)
        if consume:
            if not self.replay.add(f"tok:{claims['jti']}", claims["exp"] + self.skew):
                raise VerificationError("token_replay", "token already used")
            if claims.get("plan_id") and claims.get("step_id"):
                key = f"step:{claims['plan_id']}:{claims['step_id']}"
                if not self.replay.add(key, int(self.clock()) + 30 * 86400):
                    raise VerificationError("step_already_executed", "this plan step was already executed", 409)
        return claims

    def verify_data_access(self, token: str, proof: str | None, *, method: str, url: str, table: str) -> dict[str, Any]:
        claims = self._verify_token(token, TYP_DATA)
        if table not in (claims.get("tables") or []):
            raise VerificationError("table_not_allowed", f"token does not grant access to {table}", 403)
        self._check_policy(claims)
        self._check_proof(claims, token, proof, method, url)
        return claims


def apply_data_scope(rows: list[dict[str, Any]], claims: dict[str, Any], table: str) -> list[dict[str, Any]]:
    """Apply row filters (equality) and column allow-list from a verified data_access token."""
    filters = (claims.get("row_filters") or {}).get(table) or {}
    columns = (claims.get("columns") or {}).get(table)
    out = []
    for row in rows:
        if all(str(row.get(col)) == str(val) for col, val in filters.items()):
            out.append({k: v for k, v in row.items() if columns is None or k in columns})
    return out
