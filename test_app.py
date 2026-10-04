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


def test_gateway_token_authorizes_create_user(monkeypatch):
    monkeypatch.setattr(bank_module, "BANK_GATEWAY_URL", "http://gateway")

    class GatewayResponse:
        status_code = 200

        def json(self):
            params = {"email": "agent@example.com", "name": "Agent User", "initial_balance": "7.00"}
            return {"claims": {"service": "mini-bank", "action": "user.create", "params_hash": bank_module._params_hash(params)}}

    monkeypatch.setattr(bank_module.httpx, "post", lambda *args, **kwargs: GatewayResponse())
    r = client.post(
        "/users",
        headers={"Authorization": "GatewayAction test-token"},
        json={"email": "agent@example.com", "name": "Agent User", "initial_balance": "7.00"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["email"] == "agent@example.com"
    assert r.json()["account"]["balance"] == "7.00"


def test_gateway_token_params_must_match(monkeypatch):
    monkeypatch.setattr(bank_module, "BANK_GATEWAY_URL", "http://gateway")

    class GatewayResponse:
        status_code = 200

        def json(self):
            params = {"email": "other@example.com", "name": "Other", "initial_balance": "1.00"}
            return {"claims": {"service": "mini-bank", "action": "user.create", "params_hash": bank_module._params_hash(params)}}

    monkeypatch.setattr(bank_module.httpx, "post", lambda *args, **kwargs: GatewayResponse())
    r = client.post(
        "/users",
        headers={"Authorization": "GatewayAction test-token"},
        json={"email": "agent@example.com", "name": "Agent User", "initial_balance": "7.00"},
    )
    assert r.status_code == 403
