"""
SENG 473 — Information Security | Final Project
Team Members:
  - Abdisamed Ahmed Mohamud  (230208709)
  - Suad Abdırahman          (220208783)
  - Manar Algburi            (220208935)

Zero Trust Policy Engine
------------------------
Responsibilities:
  - Define access policies for each resource
  - Evaluate incoming requests against those policies
  - Compute a risk score for every decision
  - Enforce role, device-trust, and time-window restrictions
"""

from datetime import datetime

from flask import Flask, jsonify, request

app = Flask(__name__)

# ── Access Policies ───────────────────────────────────────────────────────────
# Each policy maps a logical resource name to a set of rules.
POLICIES = {
    "public-data": {
        "name":                    "Public Data Access",
        "resource":                "public",
        "allowed_roles":           ["viewer", "employee", "admin"],
        "requires_trusted_device": False,
        "time_restriction":        None,
        "description":             "Public company info — open to all authenticated users.",
    },
    "employee-portal": {
        "name":                    "Employee Portal",
        "resource":                "employee",
        "allowed_roles":           ["employee", "admin"],
        "requires_trusted_device": False,
        "time_restriction":        None,
        "description":             "Internal employee resources — restricted to staff.",
    },
    "admin-panel": {
        "name":                    "Admin Control Panel",
        "resource":                "admin",
        "allowed_roles":           ["admin"],
        "requires_trusted_device": True,
        "time_restriction":        None,
        "description":             "System administration — admins with trusted devices only.",
    },
    "financial-data": {
        "name":                    "Financial Records",
        "resource":                "finance",
        "allowed_roles":           ["admin"],
        "requires_trusted_device": True,
        "time_restriction":        {"start": 8, "end": 22},   # 08:00–22:00 UTC
        "description":             "Sensitive financials — admin, trusted device, business hours.",
    },
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def compute_risk_score(role: str, resource: str, device_trusted: bool, hour: int) -> int:
    """Return a 0-100 risk score.  Higher means more risky."""
    score = 0

    # Role risk contribution
    score += {"viewer": 20, "employee": 10, "admin": 5}.get(role, 30)

    # Resource sensitivity
    score += {"public": 5, "employee": 20, "admin": 40, "finance": 50}.get(resource, 30)

    # Untrusted device is a big red flag
    if not device_trusted:
        score += 30

    # Off-hours access increases risk
    if hour < 6 or hour > 22:
        score += 15

    return min(score, 100)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "healthy", "service": "policy-engine"})


@app.route("/policies")
def list_policies():
    return jsonify({"policies": list(POLICIES.values())})


@app.route("/evaluate", methods=["POST"])
def evaluate():
    data           = request.get_json() or {}
    username       = data.get("username", "anonymous")
    role           = data.get("role", "")
    resource       = data.get("resource", "")
    device_trusted = data.get("device_trusted", False)
    hour           = datetime.utcnow().hour

    # Find matching policy
    policy = next((p for p in POLICIES.values() if p["resource"] == resource), None)

    if not policy:
        return jsonify({
            "allowed":     False,
            "reason":      f'No policy defined for resource "{resource}".',
            "risk_score":  100,
            "policy_name": None,
        })

    risk = compute_risk_score(role, resource, device_trusted, hour)

    # ── Rule 1: Role check ─────────────────────────────────────────────────
    if role not in policy["allowed_roles"]:
        return jsonify({
            "allowed":     False,
            "reason":      (
                f'Role "{role}" is not permitted. '
                f'Required: {policy["allowed_roles"]}.'
            ),
            "risk_score":  risk,
            "policy_name": policy["name"],
        })

    # ── Rule 2: Trusted-device check ───────────────────────────────────────
    if policy["requires_trusted_device"] and not device_trusted:
        return jsonify({
            "allowed":     False,
            "reason":      "This resource requires a trusted (registered) device.",
            "risk_score":  risk,
            "policy_name": policy["name"],
        })

    # ── Rule 3: Time-window check ──────────────────────────────────────────
    if policy["time_restriction"]:
        start, end = policy["time_restriction"]["start"], policy["time_restriction"]["end"]
        if not (start <= hour <= end):
            return jsonify({
                "allowed":     False,
                "reason":      f"Access allowed only between {start:02d}:00 and {end:02d}:00 UTC.",
                "risk_score":  risk,
                "policy_name": policy["name"],
            })

    # ── All rules passed ───────────────────────────────────────────────────
    return jsonify({
        "allowed":             True,
        "reason":              "All Zero Trust policy checks passed.",
        "risk_score":          risk,
        "policy_name":         policy["name"],
        "policy_description":  policy["description"],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
