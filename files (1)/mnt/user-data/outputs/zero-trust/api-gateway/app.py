"""
SENG 473 — Information Security | Final Project
Team Members:
  - Abdisamed Ahmed Mohamud  (230208709)
  - Suad Abdırahman          (220208783)
  - Manar Algburi            (220208935)

Zero Trust API Gateway
-----------------------
This is the ONLY service exposed to the outside world.

For every protected request it:
  1. Extracts the Bearer JWT from the Authorization header
  2. Calls the Auth Service  → verifies the token & device trust
  3. Calls the Policy Engine → evaluates role, device, time rules
  4. If approved, calls the Resource Service and returns the data
  5. Logs every decision in an in-memory audit trail

It also serves the frontend dashboard at GET /.
"""

import os
import uuid
from collections import deque
from datetime import datetime

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

AUTH_URL     = os.environ.get("AUTH_SERVICE_URL",     "http://auth-service:5001")
POLICY_URL   = os.environ.get("POLICY_ENGINE_URL",    "http://policy-engine:5002")
RESOURCE_URL = os.environ.get("RESOURCE_SERVICE_URL", "http://resource-service:5003")

# ── Audit log (last 100 entries) ──────────────────────────────────────────────
audit_log: deque = deque(maxlen=100)


def log(username: str, resource: str, decision: str, reason: str,
        risk: int, ip: str) -> dict:
    entry = {
        "id":         str(uuid.uuid4())[:8],
        "timestamp":  datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "username":   username,
        "resource":   resource,
        "decision":   decision,
        "reason":     reason,
        "risk_score": risk,
        "ip":         ip,
    }
    audit_log.appendleft(entry)
    return entry


# ── Frontend ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "service": "api-gateway"})


# ── Auth proxy endpoints ───────────────────────────────────────────────────────

@app.route("/auth/login", methods=["POST"])
def login():
    data      = request.get_json() or {}
    device_id = (data.get("device_id")
                 or request.headers.get("X-Device-ID")
                 or str(uuid.uuid4()))
    data["device_id"] = device_id

    try:
        resp = requests.post(f"{AUTH_URL}/login", json=data, timeout=5)
        return jsonify(resp.json()), resp.status_code
    except requests.RequestException as exc:
        return jsonify({"error": f"Auth service unavailable: {exc}"}), 503


@app.route("/auth/logout", methods=["POST"])
def logout():
    data = request.get_json() or {}
    # Accept token from header or body
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        data["token"] = header[7:]

    log(
        username=data.get("username", "unknown"),
        resource="[logout]",
        decision="ALLOWED",
        reason="User initiated logout",
        risk=0,
        ip=request.remote_addr or "unknown",
    )
    try:
        resp = requests.post(f"{AUTH_URL}/logout", json=data, timeout=5)
        return jsonify(resp.json()), resp.status_code
    except requests.RequestException:
        return jsonify({"message": "Logged out"}), 200


# ── Protected resource endpoint ───────────────────────────────────────────────

@app.route("/api/resources/<resource>")
def get_resource(resource: str):
    ip = request.remote_addr or "unknown"

    # ── Step 1: Require a Bearer token ────────────────────────────────────
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        log("anonymous", resource, "DENIED", "No authentication token provided", 100, ip)
        return jsonify({"error": "Authentication required — provide a Bearer token."}), 401

    token = header[7:]

    # ── Step 2: Verify token with Auth Service ────────────────────────────
    try:
        auth_resp = requests.post(f"{AUTH_URL}/verify", json={"token": token}, timeout=5)
        auth_data = auth_resp.json()
    except requests.RequestException:
        log("unknown", resource, "DENIED", "Auth service unreachable", 100, ip)
        return jsonify({"error": "Authentication service unavailable"}), 503

    if not auth_data.get("valid"):
        error = auth_data.get("error", "Invalid token")
        log("unknown", resource, "DENIED", error, 100, ip)
        return jsonify({"error": error, "zt_step": "token_verification_failed"}), 401

    username       = auth_data["username"]
    role           = auth_data["role"]
    device_id      = auth_data.get("device_id", "")
    device_trusted = auth_data.get("device_trusted", False)

    # ── Step 3: Evaluate policy ───────────────────────────────────────────
    try:
        pol_resp = requests.post(
            f"{POLICY_URL}/evaluate",
            json={
                "username":       username,
                "role":           role,
                "resource":       resource,
                "device_id":      device_id,
                "device_trusted": device_trusted,
                "ip_address":     ip,
            },
            timeout=5,
        )
        pol_data = pol_resp.json()
    except requests.RequestException:
        log(username, resource, "DENIED", "Policy engine unreachable", 100, ip)
        return jsonify({"error": "Policy engine unavailable"}), 503

    risk       = pol_data.get("risk_score", 50)
    pol_name   = pol_data.get("policy_name", "")
    reason     = pol_data.get("reason", "")

    if not pol_data.get("allowed"):
        log(username, resource, "DENIED", reason, risk, ip)
        return jsonify({
            "error":      "Access denied",
            "reason":     reason,
            "policy":     pol_name,
            "risk_score": risk,
            "zt_step":    "policy_evaluation_failed",
        }), 403

    # ── Step 4: Fetch resource ────────────────────────────────────────────
    try:
        res_resp  = requests.get(f"{RESOURCE_URL}/{resource}", timeout=5)
        res_data  = res_resp.json()
    except requests.RequestException:
        log(username, resource, "DENIED", "Resource service unreachable", 50, ip)
        return jsonify({"error": "Resource service unavailable"}), 503

    # ── Step 5: Log success & return ──────────────────────────────────────
    entry = log(username, resource, "ALLOWED", reason, risk, ip)

    return jsonify({
        **res_data,
        "zt_metadata": {
            "username":       username,
            "role":           role,
            "device_id":      device_id,
            "device_trusted": device_trusted,
            "policy":         pol_name,
            "risk_score":     risk,
            "access_id":      entry["id"],
        },
    })


# ── Utility endpoints ─────────────────────────────────────────────────────────

@app.route("/api/logs")
def get_logs():
    return jsonify({"logs": list(audit_log)})


@app.route("/api/policies")
def get_policies():
    try:
        resp = requests.get(f"{POLICY_URL}/policies", timeout=5)
        return jsonify(resp.json())
    except requests.RequestException:
        return jsonify({"error": "Policy engine unavailable"}), 503


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
