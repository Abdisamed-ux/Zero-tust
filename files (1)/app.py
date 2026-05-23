"""
SENG 473 — Information Security | Final Project
Team Members:
  - Abdisamed Ahmed Mohamud  (230208709)
  - Suad Abdırahman          (220208783)
  - Manar Algburi            (220208935)

Zero Trust Auth Service
-----------------------
Responsibilities:
  - Validate user credentials
  - Issue short-lived JWT access tokens
  - Register & verify trusted devices
  - Revoke tokens on logout
"""

import os
import uuid
from datetime import datetime, timedelta

import bcrypt
import jwt
from flask import Flask, jsonify, request

app = Flask(__name__)

JWT_SECRET            = os.environ.get("JWT_SECRET", "ZeroTrustSecretKey2024!")
JWT_ALGORITHM         = "HS256"
TOKEN_EXPIRE_MINUTES  = int(os.environ.get("TOKEN_EXPIRE_MINUTES", "2"))  # short for demo

# ── In-memory stores (use a DB in production) ─────────────────────────────────
users        = {}   # username -> { password_hash, role, trusted_devices[] }
revoked_jtis = set()

def init_users():
    """Seed default demo users."""
    defaults = [
        ("admin",   "Admin@123",   "admin"),
        ("alice",   "Alice@123",   "employee"),
        ("bob",     "Bob@123",     "employee"),
        ("charlie", "Charlie@123", "viewer"),
    ]
    for uname, pw, role in defaults:
        pw_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
        users[uname] = {
            "password_hash":   pw_hash,
            "role":            role,
            "trusted_devices": [],
        }

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "healthy", "service": "auth-service"})


@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    device_id = data.get("device_id") or str(uuid.uuid4())

    user = users.get(username)
    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return jsonify({"error": "Invalid credentials"}), 401

    # Register device as trusted on first login from that device
    if device_id not in user["trusted_devices"]:
        user["trusted_devices"].append(device_id)

    now = datetime.utcnow()
    payload = {
        "sub":       username,
        "role":      user["role"],
        "device_id": device_id,
        "jti":       str(uuid.uuid4()),
        "iat":       now,
        "exp":       now + timedelta(minutes=TOKEN_EXPIRE_MINUTES),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return jsonify({
        "access_token": token,
        "token_type":   "Bearer",
        "expires_in":   TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "username":        username,
            "role":            user["role"],
            "device_id":       device_id,
            "trusted_devices": user["trusted_devices"],
        },
    })


@app.route("/verify", methods=["POST"])
def verify():
    data  = request.get_json() or {}
    token = data.get("token", "")

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "Token expired"}), 401
    except jwt.InvalidTokenError as exc:
        return jsonify({"valid": False, "error": str(exc)}), 401

    if payload.get("jti") in revoked_jtis:
        return jsonify({"valid": False, "error": "Token has been revoked"}), 401

    username   = payload["sub"]
    device_id  = payload.get("device_id", "")
    user       = users.get(username)

    if not user:
        return jsonify({"valid": False, "error": "User not found"}), 401

    device_trusted = device_id in user.get("trusted_devices", [])

    return jsonify({
        "valid":          True,
        "username":       username,
        "role":           payload["role"],
        "device_id":      device_id,
        "device_trusted": device_trusted,
        "expires_at":     payload["exp"],
    })


@app.route("/logout", methods=["POST"])
def logout():
    data  = request.get_json() or {}
    token = data.get("token", "")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        revoked_jtis.add(payload["jti"])
    except jwt.InvalidTokenError:
        pass  # token already invalid; that's fine
    return jsonify({"message": "Logged out successfully"})


# ── Startup ───────────────────────────────────────────────────────────────────
init_users()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
