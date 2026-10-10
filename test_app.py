import os
import tempfile

os.environ["BANK_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

from concurrent.futures import ThreadPoolExecutor  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

import app as bank_module  # noqa: E402
from app import app  # noqa: E402

client = TestClient(app)


def new_account(owner, balance="0"):
    r = client.post("/accounts", json={"owner": owner, "initial_balance": balance})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def balance(account_id):
    return client.get(f"/accounts/{account_id}").json()["balance"]


def test_transfer_moves_money():
    a, b = new_account("Ala", "100.00"), new_account("Bartek")
    r = client.post("/transfers", json={"from_account": a, "to_account": b, "amount": "30.25", "title": "Obiad"})
    assert r.status_code == 201
    assert balance(a) == "69.75"
    assert balance(b) == "30.25"
    hist = client.get(f"/accounts/{b}/history").json()
    assert hist[0]["amount"] == "+30.25" and hist[0]["counterparty"] == a


def test_insufficient_funds_rejected():
    a, b = new_account("Celina", "10"), new_account("Darek")
    r = client.post("/transfers", json={"from_account": a, "to_account": b, "amount": "10.01"})
    assert r.status_code == 409
    assert balance(a) == "10.00" and balance(b) == "0.00"


def test_invalid_requests():
    a = new_account("Ewa", "5")
    assert client.post("/transfers", json={"from_account": a, "to_account": a, "amount": "1"}).status_code == 400
    assert client.post("/transfers", json={"from_account": a, "to_account": 99999, "amount": "1"}).status_code == 404
    assert client.post("/transfers", json={"from_account": a, "to_account": a, "amount": "-1"}).status_code == 422
    assert client.post(f"/accounts/{a}/deposit", json={"amount": "0.001"}).status_code == 422


def test_deposit():
    a = new_account("Franek")
    client.post(f"/accounts/{a}/deposit", json={"amount": "12.5"})
    assert balance(a) == "12.50"


def test_concurrent_transfers_never_overdraw():
    a, b = new_account("Gosia", "100"), new_account("Henio")

    def send(_):
        return client.post("/transfers", json={"from_account": a, "to_account": b, "amount": "1"}).status_code

    with ThreadPoolExecutor(20) as pool:
        codes = list(pool.map(send, range(150)))
    assert codes.count(201) == 100
    assert balance(a) == "0.00" and balance(b) == "100.00"


def test_operations_feed():
    a, b = new_account("Iza", "50"), new_account("Janek")
    client.post("/transfers", json={"from_account": a, "to_account": b, "amount": "5", "title": "Kawa"})
    ops = client.get("/operations?limit=5").json()
    assert ops[0]["kind"] == "transfer" and ops[0]["from_owner"] == "Iza" and ops[0]["to_owner"] == "Janek"
    assert ops[0]["amount"] == "5.00" and ops[0]["title"] == "Kawa"


def test_close_empty_account():
    a = new_account("Radek")
    r = client.delete(f"/accounts/{a}")
    assert r.status_code == 200, r.text
    assert r.json()["closed"]["closed_at"] and r.json()["moved_balance"] is None
    assert a not in [x["id"] for x in client.get("/accounts").json()]
    assert a in [x["id"] for x in client.get("/accounts?include_closed=true").json()]
    assert client.get(f"/accounts/{a}").json()["closed_at"]  # dane i historia nadal dostępne
    assert client.get(f"/accounts/{a}/history").status_code == 200


def test_close_account_with_money_requires_target():
    a, b = new_account("Sara", "40.10"), new_account("Tomek", "1")
    r = client.delete(f"/accounts/{a}")
    assert r.status_code == 409 and "40.10" in r.json()["detail"]
    assert client.get(f"/accounts/{a}").json()["closed_at"] is None  # nic się nie zmieniło

    assert client.delete(f"/accounts/{a}?transfer_to={a}").status_code == 400
    assert client.delete(f"/accounts/{a}?transfer_to=99999").status_code == 404

    r = client.delete(f"/accounts/{a}?transfer_to={b}")
    assert r.status_code == 200, r.text
    assert r.json()["moved_balance"] == {"to_account": b, "amount": "40.10"}
    assert balance(a) == "0.00" and balance(b) == "41.10"
    assert client.get(f"/accounts/{b}/history").json()[0]["title"] == "Zamknięcie konta"


def test_closed_account_is_frozen():
    a, b = new_account("Ula", "10"), new_account("Wiktor")
    client.delete(f"/accounts/{b}")
    assert client.post("/transfers", json={"from_account": a, "to_account": b, "amount": "1"}).status_code == 410
    assert client.post("/transfers", json={"from_account": b, "to_account": a, "amount": "1"}).status_code == 410
    assert client.post(f"/accounts/{b}/deposit", json={"amount": "5"}).status_code == 410
    assert client.delete(f"/accounts/{b}").status_code == 410
    assert client.delete(f"/accounts/{a}?transfer_to={b}").status_code == 410
    assert balance(a) == "10.00"
    assert balance(a) == "10.00"


# ---------- gateway mode: local verification of signed, sender-constrained tokens ----------

import secrets  # noqa: E402
import time  # noqa: E402

import pytest  # noqa: E402

from wwg_sdk import AgentClient, GatewayVerifier, MemoryReplayStore, jwk_thumbprint, params_hash, public_jwk, sign_jws  # noqa: E402

ISSUER = "wwgateway-test"


class FakeGateway:
    """Issues tokens exactly like the real gateway (EdDSA, cnf, plan claims) for bank-side tests."""

    def __init__(self):
        self.key = AgentClient.generate_key()
        self.kid = "test-kid"
        self.agent = AgentClient("agent-1", AgentClient.generate_key())
        self.revoked: list[str] = []
        self.tolerance = "high"

    def fetch(self, url):
        if url.endswith("/.well-known/jwks.json"):
            return {"keys": [{**public_jwk(self.key.public_key()), "kid": self.kid, "alg": "EdDSA"}]}
        now = int(time.time())
        snap = {"iss": ISSUER, "iat": now, "exp": now + 10, "risk_tolerance": self.tolerance, "system_risk_tolerances": {},
                "revoked_jti": self.revoked, "revoked_agents": [], "revoked_plans": []}
        return {"snapshot": sign_jws(self.key, {"kid": self.kid, "typ": "wwg-policy+jwt"}, snap)}

    def token(self, typ, claims, ttl=30):
        now = int(time.time())
        payload = {"iss": ISSUER, "aud": "mini-bank", "sub": "agent-1", "iat": now, "nbf": now, "exp": now + ttl,
                   "jti": "tok_" + secrets.token_urlsafe(8), "risk_level": "medium", "cnf": {"jkt": jwk_thumbprint(self.agent.jwk)}, **claims}
        return sign_jws(self.key, {"kid": self.kid, "typ": typ}, payload)

    def action(self, action, params, **extra):
        return self.token("wwg-action+jwt", {"action": action, "params_hash": params_hash(params), **extra})

    def data(self, tables, row_filters=None, columns=None):
        return self.token("wwg-data+jwt", {"tables": tables, "row_filters": row_filters or {}, "columns": columns or {}})

    def headers(self, scheme, token, method, path):
        return {"Authorization": f"{scheme} {token}", "WWG-Proof": self.agent.proof(method, "http://testserver" + path, token)}


@pytest.fixture
def gw(monkeypatch):
    fake = FakeGateway()
    verifier = GatewayVerifier(gateway_url="http://gateway", issuer=ISSUER, audience="mini-bank", replay_store=MemoryReplayStore(), fetch_json=fake.fetch)
    monkeypatch.setattr(bank_module, "BANK_GATEWAY_URL", "http://gateway")
    monkeypatch.setattr(bank_module, "gateway_verifier", lambda: verifier)
    return fake


USER = {"email": "agent@example.com", "name": "Agent User", "initial_balance": "7.00"}


def test_gateway_token_authorizes_create_user(gw):
    token = gw.action("user.create", USER)
    r = client.post("/users", headers=gw.headers("GatewayAction", token, "POST", "/users"), json=USER)
    assert r.status_code == 201, r.text
    assert r.json()["account"]["balance"] == "7.00"


def test_gateway_rejects_missing_token_and_missing_proof(gw):
    assert client.post("/users", json=USER).json()["detail"]["error"] == "token_required"
    token = gw.action("user.create", USER)
    r = client.post("/users", headers={"Authorization": f"GatewayAction {token}"}, json=USER)
    assert r.status_code == 401 and r.json()["detail"]["error"] == "proof_missing"


def test_gateway_token_params_must_match(gw):
    token = gw.action("user.create", {**USER, "email": "other@example.com"})
    r = client.post("/users", headers=gw.headers("GatewayAction", token, "POST", "/users"), json=USER)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "params_mismatch"


def test_gateway_token_is_single_use(gw):
    token = gw.action("user.create", USER)
    assert client.post("/users", headers=gw.headers("GatewayAction", token, "POST", "/users"), json=USER).status_code == 201
    replay = client.post("/users", headers=gw.headers("GatewayAction", token, "POST", "/users"), json=USER)
    assert replay.status_code == 401 and replay.json()["detail"]["error"] == "token_replay"


def test_stolen_token_without_agent_key_is_useless(gw):
    token = gw.action("user.create", USER)
    thief = AgentClient("agent-1", AgentClient.generate_key())
    r = client.post("/users", headers={"Authorization": f"GatewayAction {token}", "WWG-Proof": thief.proof("POST", "http://testserver/users", token)}, json=USER)
    assert r.status_code == 401 and r.json()["detail"]["error"] == "proof_key_mismatch"


def test_token_for_another_action_or_system_is_rejected(gw):
    params = {"from_account": 1, "to_account": 2, "amount": "1.00", "title": ""}
    token = gw.action("deposit.create", params)
    r = client.post("/transfers", headers=gw.headers("GatewayAction", token, "POST", "/transfers"), json=params)
    assert r.json()["detail"]["error"] == "wrong_action"
    other = gw.token("wwg-action+jwt", {"aud": "card-system", "action": "transfer.create", "params_hash": params_hash(params)})
    r = client.post("/transfers", headers=gw.headers("GatewayAction", other, "POST", "/transfers"), json=params)
    assert r.json()["detail"]["error"] == "wrong_audience"


def test_revocation_and_risk_tolerance_apply_to_issued_tokens(gw):
    token = gw.action("user.create", USER)
    gw.revoked.append(__import__("json").loads(__import__("base64").urlsafe_b64decode(token.split(".")[1] + "=="))["jti"])
    bank_module.gateway_verifier()._snapshot = None
    assert client.post("/users", headers=gw.headers("GatewayAction", token, "POST", "/users"), json=USER).json()["detail"]["error"] == "revoked"
    gw.revoked.clear()
    gw.tolerance = "low"
    bank_module.gateway_verifier()._snapshot = None
    token2 = gw.action("user.create", USER)
    assert client.post("/users", headers=gw.headers("GatewayAction", token2, "POST", "/users"), json=USER).json()["detail"]["error"] == "risk_tolerance"


def test_reads_require_data_token_and_apply_row_and_column_scope(gw, monkeypatch):
    monkeypatch.setattr(bank_module, "BANK_GATEWAY_URL", "")
    ala, ola = new_account("Ala-scope", "5.00"), new_account("Ola-scope", "6.00")
    monkeypatch.setattr(bank_module, "BANK_GATEWAY_URL", "http://gateway")
    assert client.get("/accounts").json()["detail"]["error"] == "token_required"
    token = gw.data(["accounts", "operations"], row_filters={"accounts": {"owner": "Ala-scope"}}, columns={"accounts": ["id", "owner", "balance"]})
    rows = client.get("/accounts", headers=gw.headers("GatewayData", token, "GET", "/accounts")).json()
    assert rows == [{"id": ala, "owner": "Ala-scope", "balance": "5.00"}]
    hidden = client.get(f"/accounts/{ola}", headers=gw.headers("GatewayData", token, "GET", f"/accounts/{ola}"))
    assert hidden.status_code == 404
    history = client.get(f"/accounts/{ola}/history", headers=gw.headers("GatewayData", token, "GET", f"/accounts/{ola}/history"))
    assert history.status_code == 404
    accounts_only = gw.data(["accounts"])
    assert client.get("/operations", headers=gw.headers("GatewayData", accounts_only, "GET", "/operations")).json()["detail"]["error"] == "table_not_allowed"
