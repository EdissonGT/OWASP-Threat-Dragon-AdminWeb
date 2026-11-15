#!/usr/bin/env python3
"""Revisa que el repositorio no contenga IPs, llaves privadas ni secretos evidentes."""
import pathlib, re, sys

IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
KEY = re.compile(r"BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}")
errors = 0
for p in pathlib.Path(".").rglob("*"):
    if not p.is_file() or ".git" in p.parts or p.suffix in {".png", ".jpg"}:
        continue
    text = p.read_text(encoding="utf-8", errors="ignore")
    if KEY.search(text):
        print(f"[ERROR] {p}: posible secreto"); errors += 1
    for ip in set(IP.findall(text)) - {"0.0.0.0", "127.0.0.1"}:
        print(f"[AVISO] {p}: posible IP {ip}")
print("OK" if not errors else "FALLÓ")
sys.exit(1 if errors else 0)
