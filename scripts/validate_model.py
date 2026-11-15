#!/usr/bin/env python3
"""Valida que los modelos JSON sean válidos y que no contengan IPs ni llaves privadas."""
import glob, json, re, sys

IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
KEY = re.compile(r"BEGIN [A-Z ]*PRIVATE KEY")
errors = 0
for path in sorted(glob.glob("threat-models/**/*.json", recursive=True)):
    text = open(path, encoding="utf-8").read()
    try:
        json.loads(text)
    except json.JSONDecodeError as e:
        print(f"[ERROR] {path}: JSON inválido: {e}"); errors += 1; continue
    if KEY.search(text):
        print(f"[ERROR] {path}: contiene una llave privada"); errors += 1
    for ip in set(IP.findall(text)):
        print(f"[AVISO] {path}: posible IP: {ip}")
    print(f"[OK] {path}")
sys.exit(1 if errors else 0)
