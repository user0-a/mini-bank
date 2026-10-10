"""Prosty serwis bankowy: konta, wpłaty i przelewy między kontami.

Kwoty przyjmowane są w złotych (np. "12.50"), a przechowywane jako liczba
całkowita groszy, żeby uniknąć błędów zaokrągleń.
"""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any

try:
    import httpx  # noqa: F401  (used by wwg_sdk to reach the gateway)
    from fastapi import FastAPI, Header, HTTPException, Request
    from fastapi.responses import FileResponse
    from pydantic import BaseModel, Field, field_validator
except ImportError:
    raise SystemExit(
        "Brakuje bibliotek. Zainstaluj je poleceniem:\n"
        "    python3 -m pip install -r requirements.txt"
    )

DB_PATH = os.environ.get("BANK_DB", "bank.db")
BANK_GATEWAY_URL = os.environ.get("BANK_GATEWAY_URL", "").rstrip("/")
BANK_SERVICE_ID = os.environ.get("BANK_SERVICE_ID", "mini-bank")
BANK_GATEWAY_ISSUER = os.environ.get("BANK_GATEWAY_ISSUER", "wwgateway-dev")
BANK_PROTECT_READS = os.environ.get("BANK_PROTECT_READS", "1") == "1"

from wwg_sdk import GatewayVerifier, SQLiteReplayStore, VerificationError, apply_data_scope  # noqa: E402

app = FastAPI(title="Mini Bank")


# ---------- baza danych ----------

def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, isolation_level=None)  # sami sterujemy transakcjami
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def transaction():
    """Transakcja z blokadą zapisu (BEGIN IMMEDIATE) — chroni przed wyścigami przy przelewach."""
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def init_db() -> None:
    conn = connect()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS accounts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            owner      TEXT    NOT NULL,
            balance    INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
            created_at TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS operations (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            kind         TEXT    NOT NULL CHECK (kind IN ('deposit', 'transfer')),
            from_account INTEGER REFERENCES accounts(id),
            to_account   INTEGER NOT NULL REFERENCES accounts(id),
            amount       INTEGER NOT NULL CHECK (amount > 0),
            title        TEXT    NOT NULL DEFAULT '',
            created_at   TEXT    NOT NULL
        );
        """
    )
    # migracja istniejącej bazy: kolumna z datą zamknięcia konta (NULL = konto aktywne)
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(accounts)")}
    if "closed_at" not in columns:
        conn.execute("ALTER TABLE accounts ADD COLUMN closed_at TEXT")
    conn.close()


init_db()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def to_grosze(value: Decimal) -> int:
    return int((value * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def to_pln(grosze: int) -> str:
    return f"{Decimal(grosze) / 100:.2f}"


_verifier: GatewayVerifier | None = None


def gateway_verifier() -> GatewayVerifier:
    """Local token verification (EdDSA via JWKS, proof of possession, single use, live policy)."""
    global _verifier
    if _verifier is None or _verifier.gateway_url != BANK_GATEWAY_URL:
        _verifier = GatewayVerifier(
            gateway_url=BANK_GATEWAY_URL,
            issuer=BANK_GATEWAY_ISSUER,
            audience=BANK_SERVICE_ID,
            replay_store=SQLiteReplayStore(DB_PATH),
        )
    return _verifier


def _token(authorization: str | None, scheme: str) -> str:
    prefix = scheme + " "
    if not authorization or not authorization.startswith(prefix):
        raise HTTPException(401, {"error": "token_required", "message": f"{scheme} token required"})
    return authorization[len(prefix):]


def require_gateway_action(request: Request, expected_action: str, params: dict[str, Any], authorization: str | None, proof: str | None) -> dict[str, Any] | None:
    """Gateway mode (BANK_GATEWAY_URL set): every protected write needs
    Authorization: GatewayAction <token> and WWG-Proof: <proof signed by the agent key>.
    Without BANK_GATEWAY_URL the bank runs standalone for local development.
    """
    if not BANK_GATEWAY_URL:
        return None
    token = _token(authorization, "GatewayAction")
    try:
        return gateway_verifier().verify_action(token, proof, method=request.method, url=str(request.url), action=expected_action, params=params)
    except VerificationError as exc:
        raise HTTPException(exc.status, {"error": exc.code, "message": exc.message}) from exc


def require_gateway_data(request: Request, table: str, authorization: str | None, proof: str | None) -> dict[str, Any] | None:
    """Reads need Authorization: GatewayData <data_access_token> in gateway mode (BANK_PROTECT_READS=1)."""
    if not BANK_GATEWAY_URL or not BANK_PROTECT_READS:
        return None
    token = _token(authorization, "GatewayData")
    try:
        return gateway_verifier().verify_data_access(token, proof, method=request.method, url=str(request.url), table=table)
    except VerificationError as exc:
        raise HTTPException(exc.status, {"error": exc.code, "message": exc.message}) from exc


def scoped(rows: list[dict[str, Any]], claims: dict[str, Any] | None, table: str) -> list[dict[str, Any]]:
    return rows if claims is None else apply_data_scope(rows, claims, table)


def account_out(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "owner": row["owner"],
        "balance": to_pln(row["balance"]),
        "created_at": row["created_at"],
        "closed_at": row["closed_at"],
    }


def get_account(conn: sqlite3.Connection, account_id: int, allow_closed: bool = False) -> sqlite3.Row:
    """Zwraca konto. Domyślnie tylko aktywne — na zamknięte nie da się wpłacać ani przelewać."""
    row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    if row is None:
        raise HTTPException(404, f"Konto {account_id} nie istnieje")
    if row["closed_at"] is not None and not allow_closed:
        raise HTTPException(410, f"Konto {account_id} jest zamknięte")
    return row


# ---------- modele żądań ----------

class Amount(BaseModel):
    amount: Decimal = Field(gt=0, max_digits=12, decimal_places=2, description="Kwota w PLN, np. 12.50")


class NewAccount(BaseModel):
    owner: str = Field(min_length=1, max_length=100)
    initial_balance: Decimal = Field(default=Decimal("0"), ge=0, max_digits=12, decimal_places=2)

    @field_validator("owner")
    @classmethod
    def strip_owner(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Właściciel nie może być pusty")
        return v


class NewUser(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: str = Field(min_length=3, max_length=200)
    initial_balance: Decimal = Field(default=Decimal("0"), ge=0, max_digits=12, decimal_places=2)

    @field_validator("name", "email")
    @classmethod
    def strip_text(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Wartość nie może być pusta")
        return v


class Transfer(Amount):
    from_account: int
    to_account: int
    title: str = Field(default="", max_length=140)


# ---------- endpointy ----------

def create_account_record(owner: str, initial_balance: Decimal) -> dict:
    with transaction() as conn:
        cur = conn.execute(
            "INSERT INTO accounts (owner, balance, created_at) VALUES (?, ?, ?)",
            (owner, 0, now()),
        )
        account_id = cur.lastrowid
        initial = to_grosze(initial_balance)
        if initial > 0:
            conn.execute("UPDATE accounts SET balance = ? WHERE id = ?", (initial, account_id))
            conn.execute(
                "INSERT INTO operations (kind, to_account, amount, title, created_at) VALUES ('deposit', ?, ?, ?, ?)",
                (account_id, initial, "Wpłata początkowa", now()),
            )
        return account_out(get_account(conn, account_id))

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(Path(__file__).with_name("index.html"))


@app.post("/accounts", status_code=201)
def create_account(request: Request, body: NewAccount, authorization: str | None = Header(default=None), wwg_proof: str | None = Header(default=None, alias="WWG-Proof")):
    require_gateway_action(request, "account.create", {"owner": body.owner, "initial_balance": str(body.initial_balance)}, authorization, wwg_proof)
    return create_account_record(body.owner, body.initial_balance)


@app.post("/users", status_code=201)
def create_user(request: Request, body: NewUser, authorization: str | None = Header(default=None), wwg_proof: str | None = Header(default=None, alias="WWG-Proof")):
    require_gateway_action(request, "user.create", {"email": body.email, "name": body.name, "initial_balance": str(body.initial_balance)}, authorization, wwg_proof)
    account = create_account_record(body.name, body.initial_balance)
    return {"id": account["id"], "name": body.name, "email": body.email, "account": account}


@app.get("/accounts")
def list_accounts(request: Request, include_closed: bool = False, authorization: str | None = Header(default=None), wwg_proof: str | None = Header(default=None, alias="WWG-Proof")):
    claims = require_gateway_data(request, "accounts", authorization, wwg_proof)
    conn = connect()
    try:
        sql = "SELECT * FROM accounts" + ("" if include_closed else " WHERE closed_at IS NULL") + " ORDER BY id"
        return scoped([account_out(r) for r in conn.execute(sql)], claims, "accounts")
    finally:
        conn.close()


@app.get("/accounts/{account_id}")
def read_account(request: Request, account_id: int, authorization: str | None = Header(default=None), wwg_proof: str | None = Header(default=None, alias="WWG-Proof")):
    claims = require_gateway_data(request, "accounts", authorization, wwg_proof)
    conn = connect()
    try:
        rows = scoped([account_out(get_account(conn, account_id, allow_closed=True))], claims, "accounts")
        if not rows:
            raise HTTPException(404, f"Konto {account_id} nie istnieje")
        return rows[0]
    finally:
        conn.close()


@app.delete("/accounts/{account_id}")
def close_account(request: Request, account_id: int, transfer_to: int | None = None, authorization: str | None = Header(default=None), wwg_proof: str | None = Header(default=None, alias="WWG-Proof")):
    """Zamyka (usuwa) konto. Historia operacji zostaje, konto znika z listy.

    Jeśli na koncie są pieniądze, trzeba podać `transfer_to` — konto, na które
    zostanie przelane całe saldo. Wszystko dzieje się w jednej transakcji.
    """
    params = {"account_id": account_id, "transfer_to": transfer_to}
    require_gateway_action(request, "account.close", params, authorization, wwg_proof)
    with transaction() as conn:
        acc = get_account(conn, account_id)
        moved = None
        if acc["balance"] > 0:
            if transfer_to is None:
                raise HTTPException(
                    409,
                    f"Na koncie jest {to_pln(acc['balance'])} zł. Wskaż konto, na które przelać środki (transfer_to).",
                )
            if transfer_to == account_id:
                raise HTTPException(400, "Nie można przelać środków na zamykane konto")
            get_account(conn, transfer_to)
            conn.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (acc["balance"], transfer_to))
            conn.execute("UPDATE accounts SET balance = 0 WHERE id = ?", (account_id,))
            conn.execute(
                "INSERT INTO operations (kind, from_account, to_account, amount, title, created_at) "
                "VALUES ('transfer', ?, ?, ?, 'Zamknięcie konta', ?)",
                (account_id, transfer_to, acc["balance"], now()),
            )
            moved = {"to_account": transfer_to, "amount": to_pln(acc["balance"])}
        conn.execute("UPDATE accounts SET closed_at = ? WHERE id = ?", (now(), account_id))
        return {"closed": account_out(get_account(conn, account_id, allow_closed=True)), "moved_balance": moved}


@app.post("/accounts/{account_id}/deposit")
def deposit(request: Request, account_id: int, body: Amount, authorization: str | None = Header(default=None), wwg_proof: str | None = Header(default=None, alias="WWG-Proof")):
    require_gateway_action(request, "deposit.create", {"account_id": account_id, "amount": str(body.amount)}, authorization, wwg_proof)
    amount = to_grosze(body.amount)
    with transaction() as conn:
        get_account(conn, account_id)
        conn.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, account_id))
        conn.execute(
            "INSERT INTO operations (kind, to_account, amount, title, created_at) VALUES ('deposit', ?, ?, 'Wpłata', ?)",
            (account_id, amount, now()),
        )
        return account_out(get_account(conn, account_id))


@app.post("/transfers", status_code=201)
def transfer(request: Request, body: Transfer, authorization: str | None = Header(default=None), wwg_proof: str | None = Header(default=None, alias="WWG-Proof")):
    require_gateway_action(request, "transfer.create", {"from_account": body.from_account, "to_account": body.to_account, "amount": str(body.amount), "title": body.title}, authorization, wwg_proof)
    if body.from_account == body.to_account:
        raise HTTPException(400, "Nie można przelać na to samo konto")
    amount = to_grosze(body.amount)
    with transaction() as conn:
        sender = get_account(conn, body.from_account)
        get_account(conn, body.to_account)
        if sender["balance"] < amount:
            raise HTTPException(409, "Brak wystarczających środków")
        conn.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, body.from_account))
        conn.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, body.to_account))
        cur = conn.execute(
            "INSERT INTO operations (kind, from_account, to_account, amount, title, created_at) "
            "VALUES ('transfer', ?, ?, ?, ?, ?)",
            (body.from_account, body.to_account, amount, body.title.strip(), now()),
        )
        return {
            "id": cur.lastrowid,
            "from_account": body.from_account,
            "to_account": body.to_account,
            "amount": to_pln(amount),
            "title": body.title.strip(),
        }


@app.get("/operations")
def all_operations(request: Request, limit: int = 50, authorization: str | None = Header(default=None), wwg_proof: str | None = Header(default=None, alias="WWG-Proof")):
    """Wszystkie operacje w banku, od najnowszych — do podglądu „co się dzieje”."""
    claims = require_gateway_data(request, "operations", authorization, wwg_proof)
    conn = connect()
    try:
        rows = conn.execute(
            """SELECT o.*, f.owner AS from_owner, t.owner AS to_owner
               FROM operations o
               LEFT JOIN accounts f ON f.id = o.from_account
               JOIN accounts t ON t.id = o.to_account
               ORDER BY o.id DESC LIMIT ?""",
            (max(1, min(limit, 500)),),
        ).fetchall()
        return scoped([{
            "id": r["id"],
            "kind": r["kind"],
            "from_account": r["from_account"],
            "from_owner": r["from_owner"],
            "to_account": r["to_account"],
            "to_owner": r["to_owner"],
            "amount": to_pln(r["amount"]),
            "title": r["title"],
            "created_at": r["created_at"],
        } for r in rows], claims, "operations")
    finally:
        conn.close()


@app.get("/accounts/{account_id}/history")
def history(request: Request, account_id: int, authorization: str | None = Header(default=None), wwg_proof: str | None = Header(default=None, alias="WWG-Proof")):
    claims = require_gateway_data(request, "operations", authorization, wwg_proof)
    conn = connect()
    try:
        account = account_out(get_account(conn, account_id, allow_closed=True))
        # the account itself must be inside the token's row scope for "accounts"
        if claims is not None and not apply_data_scope([account], {"row_filters": claims.get("row_filters"), "columns": {}}, "accounts"):
            raise HTTPException(404, f"Konto {account_id} nie istnieje")
        rows = conn.execute(
            "SELECT * FROM operations WHERE from_account = ? OR to_account = ? ORDER BY id DESC",
            (account_id, account_id),
        ).fetchall()
        out = []
        for r in rows:
            outgoing = r["from_account"] == account_id
            out.append({
                "id": r["id"],
                "kind": r["kind"],
                "direction": "out" if outgoing else "in",
                "counterparty": r["to_account"] if outgoing else r["from_account"],
                "amount": ("-" if outgoing else "+") + to_pln(r["amount"]),
                "title": r["title"],
                "created_at": r["created_at"],
            })
        return scoped(out, claims, "operations")
    finally:
        conn.close()


# ---------- uruchomienie: python3 app.py ----------

if __name__ == "__main__":
    import argparse
    import threading
    import webbrowser

    import uvicorn

    parser = argparse.ArgumentParser(description="Mini Bank")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true", help="nie otwieraj przeglądarki")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"
    print(f"Mini Bank działa na {url}  (zatrzymanie: Ctrl+C)")
    if not args.no_browser:
        threading.Timer(1.5, webbrowser.open, args=(url,)).start()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
