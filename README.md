# Mini Bank

Prosty serwis: konta, wpłaty i przelewy między kontami (FastAPI + SQLite).

## Uruchomienie

```bash
python3 -m pip install -r requirements.txt   # tylko za pierwszym razem
python3 app.py
```

Strona otworzy się sama. Opcje: `python3 app.py --port 9000`, `python3 app.py --no-browser`.
Zatrzymanie: Ctrl+C. Można też kliknąć dwa razy `start.command` (sam zainstaluje biblioteki).

Strona: http://127.0.0.1:8000 · Dokumentacja API: http://127.0.0.1:8000/docs

## Tryb Gateway

Domyślnie bank działa samodzielnie, bez wymagania tokenów. Żeby wymusić autoryzację przez gateway dla akcji zapisu, uruchom go tak:

```bash
BANK_GATEWAY_URL=http://127.0.0.1:8001 python3 app.py --no-browser
```

Wtedy chronione akcje wymagają nagłówka:

```text
Authorization: GatewayAction <action_token>
```

Token jest walidowany w gatewayu, a bank sprawdza, czy dotyczy systemu `mini-bank`, właściwej akcji oraz tych samych parametrów żądania.

## API

| Metoda | Ścieżka | Opis |
|---|---|---|
| POST | `/accounts` | `{"owner": "Ala", "initial_balance": "100.00"}` |
| POST | `/users` | `{"name": "Ala", "email": "ala@example.com", "initial_balance": "100.00"}` |
| GET | `/accounts` | lista kont |
| GET | `/accounts/{id}` | jedno konto |
| POST | `/accounts/{id}/deposit` | `{"amount": "12.50"}` |
| POST | `/transfers` | `{"from_account": 1, "to_account": 2, "amount": "30", "title": "Obiad"}` |
| GET | `/accounts/{id}/history` | historia operacji |
| DELETE | `/accounts/{id}` | usuwa (zamyka) puste konto |
| DELETE | `/accounts/{id}?transfer_to=2` | usuwa konto z pieniędzmi — saldo idzie na konto 2 |
| GET | `/accounts?include_closed=true` | lista razem z usuniętymi kontami |

Usunięte konto znika z listy i nie można na nie wpłacać ani przelewać (odpowiedź 410),
ale jego historia zostaje, bo inne konta mają z nim operacje w historii.

Kwoty trzymane są w groszach (bez błędów zaokrągleń). Przelew odbywa się w jednej
transakcji z blokadą zapisu, więc saldo nigdy nie spadnie poniżej zera, nawet przy
wielu równoczesnych przelewach.

## Testy

```bash
pytest
```
