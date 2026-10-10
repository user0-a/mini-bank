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

Domyślnie bank działa samodzielnie. Z gatewayem:

```bash
BANK_GATEWAY_URL=http://127.0.0.1:8001 python3 app.py --no-browser
```

Wtedy bank **sam, lokalnie** weryfikuje tokeny (`wwg_sdk.py`): podpis EdDSA gatewaya (JWKS), system
docelowy, akcję, dokładne parametry, dowód posiadania klucza agenta, jednorazowość (tabela
`wwg_replay` w bazie banku) oraz podpisany snapshot polityki (odwołania, poziom ryzyka). Gdy gateway
jest niedostępny dłużej niż 30 s, bank odrzuca żądania (fail closed).

| Operacja | Nagłówki |
|---|---|
| Zapis (`/users`, `/accounts`, `/transfers`, wpłata, zamknięcie konta) | `Authorization: GatewayAction <token>`, `WWG-Proof: <dowód>` |
| Odczyt (`/accounts`, `/operations`, historia) | `Authorization: GatewayData <token>`, `WWG-Proof: <dowód>` |

Token danych ogranicza tabele, kolumny i wiersze. `BANK_PROTECT_READS=0` wyłącza ochronę odczytów
(np. żeby przeglądać stronę banku podczas demo); zapisy pozostają chronione.

Zmienne: `BANK_GATEWAY_URL`, `BANK_GATEWAY_ISSUER` (domyślnie `wwgateway-dev`), `BANK_SERVICE_ID`
(domyślnie `mini-bank`), `BANK_PROTECT_READS` (domyślnie `1`).

`wwg_sdk.py` to kopia `gateway/sdk/python/wwg_sdk.py` — aktualizować razem.

## Testy

```bash
pytest
```
