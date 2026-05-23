from datetime import datetime, timedelta
import os
import uuid

import bcrypt
import jwt
from flask import Flask, jsonify, request

app = Flask(__name__)

AUTH_SECRET = os.environ.get("AUTH_SECRET", "supersecretkey")
TOKEN_TTL = int(os.environ.get("TOKEN_TTL_SECONDS", "120"))

USERS = {
    "admin": {"password": "Admin@123", "role": "admin"},
    "alice": {"password": "Alice@123", "role": "employee"},
    "bob": {"password": "Bob@123", "role": "employee"},
    "charlie": {"password": "Charlie@123", "role": "viewer"},
}

PASSWORD_HASHES = {
    username: bcrypt.hashpw(data["password"].encode("utf-8"), bcrypt.gensalt())
    for username, data in USERS.items()
}

# JTI blacklist and trusted device registry
REVOKED_TOKENS = set()
TRUSTED_DEVICES = {username: set() for username in USERS}


def create_token(username, role, device_id):
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "role": role,
        "device_id": device_id,
        "jti": str(uuid.uuid4()),
        "iat": now.timestamp(),
        "exp": (now + timedelta(seconds=TOKEN_TTL)).timestamp(),
    }
    return jwt.encode(payload, AUTH_SECRET, algorithm="HS256")


def get_token_from_request(data):
    token = data.get("token")
    if not token:
        header = request.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            token = header[7:]
    return token


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "service": "auth-service"})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    device_id = data.get("device_id") or request.headers.get("X-Device-ID") or str(uuid.uuid4())

    if username not in USERS:
        return jsonify({"error": "Invalid username or password"}), 401

    stored_hash = PASSWORD_HASHES[username]
    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        return jsonify({"error": "Invalid username or password"}), 401

    role = USERS[username]["role"]
    TRUSTED_DEVICES[username].add(device_id)
    token = create_token(username, role, device_id)

    return jsonify({
        "token": token,
        "username": username,
        "role": role,
        "device_id": device_id,
        "device_trusted": True,
        "expires_in": TOKEN_TTL,
    }), 200


@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json() or {}
    token = get_token_from_request(data)
    if not token:
        return jsonify({"valid": False, "error": "Missing token"}), 401

    try:
        payload = jwt.decode(token, AUTH_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "error": "Invalid token"}), 401

    if payload.get("jti") in REVOKED_TOKENS:
        return jsonify({"valid": False, "error": "Token has been revoked"}), 401

    username = payload.get("sub")
    if username not in USERS:
        return jsonify({"valid": False, "error": "Unknown user"}), 401

    device_id = payload.get("device_id")
    trusted = device_id in TRUSTED_DEVICES.get(username, set())

    return jsonify({
        "valid": True,
        "username": username,
        "role": payload.get("role", ""),
        "device_id": device_id,
        "device_trusted": trusted,
    }), 200


@app.route("/logout", methods=["POST"])
def logout():
    data = request.get_json() or {}
    token = get_token_from_request(data)
    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
        payload = jwt.decode(token, AUTH_SECRET, algorithms=["HS256"], options={"verify_exp": False})
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 400

    jti = payload.get("jti")
    if jti:
        REVOKED_TOKENS.add(jti)

    return jsonify({"message": "Logged out"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
