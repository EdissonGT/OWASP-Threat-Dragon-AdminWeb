"""Ejemplo mínimo de Flask con controles de seguridad básicos.
pip install flask flask-limiter flask-talisman argon2-cffi pydantic
"""
import os
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from argon2 import PasswordHasher
from pydantic import BaseModel, Field, ValidationError

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024  # límite de tamaño
app.secret_key = os.environ["SECRET_KEY"]       # desde gestor de secretos

Talisman(app)  # HTTPS, HSTS, CSP y otros headers
limiter = Limiter(get_remote_address, app=app, default_limits=["300 per 15 minutes"])
ph = PasswordHasher()  # Argon2id


class Login(BaseModel):
    user: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


@app.post("/auth/login")
@limiter.limit("10 per 15 minutes")
def login():
    try:
        data = Login(**(request.get_json(silent=True) or {}))
    except ValidationError:
        return jsonify(error="Datos inválidos"), 400
    # Busca el hash del usuario con consulta parametrizada y verifica con ph.verify(...)
    return jsonify(error="Credenciales inválidas"), 401  # mensaje genérico


@app.errorhandler(Exception)
def handle_error(e):
    app.logger.exception(e)  # detalle solo en logs
    return jsonify(error="Error interno"), 500
