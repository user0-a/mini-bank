#!/bin/bash
# Uruchamia Mini Bank: tworzy środowisko (za pierwszym razem) i startuje serwer.
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv || { echo "Brak python3 — zainstaluj Pythona z python.org"; read; exit 1; }
  .venv/bin/pip install -q -r requirements.txt
fi
.venv/bin/python app.py
