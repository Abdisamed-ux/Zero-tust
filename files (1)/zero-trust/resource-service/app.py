"""
SENG 473 — Information Security | Final Project
Team Members:
  - Abdisamed Ahmed Mohamud  (230208709)
  - Suad Abdırahman          (220208783)
  - Manar Algburi            (220208935)

Zero Trust Resource Service
----------------------------
Simulates four protected data endpoints:
  /public   – open to all authenticated users
  /employee – internal staff resources
  /admin    – system administration data
  /finance  – sensitive financial records

NOTE: In a true Zero Trust architecture this service would ALSO verify the
JWT before responding.  Here the API Gateway is the enforcement point and the
resource service trusts only traffic from within the internal Docker network.
"""

from datetime import datetime

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "service": "resource-service"})


@app.route("/public")
def public():
    return jsonify({
        "resource":       "public",
        "title":          "Public Company Information",
        "classification": "PUBLIC",
        "accessed_at":    datetime.utcnow().isoformat() + "Z",
        "data": {
            "company":      "ZeroTrust Corp",
            "announcement": "Q2 2025 earnings call scheduled for July 15th.",
            "office_hours": "09:00–18:00 UTC, Monday–Friday",
            "contact":      "info@zerotrust-corp.example",
            "news": [
                "ZeroTrust Corp wins Best Security Innovation Award 2025",
                "New Berlin office opens next quarter",
                "Annual security-awareness training now available on the portal",
            ],
        },
    })


@app.route("/employee")
def employee():
    return jsonify({
        "resource":       "employee",
        "title":          "Employee Portal",
        "classification": "INTERNAL — CONFIDENTIAL",
        "accessed_at":    datetime.utcnow().isoformat() + "Z",
        "data": {
            "internal_tools": ["GitLab (self-hosted)", "Confluence", "Jira", "HR Portal"],
            "announcements": [
                "[INTERNAL] Team offsite: 5–7 August — registration closes Friday",
                "[INTERNAL] New remote-work security policy effective 1 July",
                "[INTERNAL] 360° performance reviews open until 30 June",
            ],
            "payroll_cycle": "Monthly — credited on the 25th",
            "vpn_endpoint":  "vpn.internal:1194 (WireGuard config in IT portal)",
        },
    })


@app.route("/admin")
def admin():
    return jsonify({
        "resource":       "admin",
        "title":          "Admin Control Panel",
        "classification": "TOP SECRET — ADMIN ONLY",
        "accessed_at":    datetime.utcnow().isoformat() + "Z",
        "data": {
            "active_users":         247,
            "failed_logins_today":  12,
            "security_alerts": [
                {"level": "MEDIUM", "message": "Unusual login pattern from 192.168.5.10"},
                {"level": "LOW",    "message": "3 accounts locked after repeated failures"},
            ],
            "service_health": {
                "auth-service":     "HEALTHY",
                "policy-engine":    "HEALTHY",
                "resource-service": "HEALTHY",
                "api-gateway":      "HEALTHY",
            },
            "pending_actions": [
                "Review 2 new device-registration requests",
                "Approve elevated-access request from alice",
            ],
        },
    })


@app.route("/finance")
def finance():
    return jsonify({
        "resource":       "finance",
        "title":          "Financial Records",
        "classification": "STRICTLY CONFIDENTIAL — FINANCE",
        "accessed_at":    datetime.utcnow().isoformat() + "Z",
        "data": {
            "q1_revenue":        "$4,250,000",
            "q2_forecast":       "$4,800,000",
            "operating_costs":   "$1,200,000",
            "net_profit_q1":     "$1,750,000",
            "remaining_budget":  "$890,000",
            "recent_transactions": [
                {"date": "2025-06-01", "amount": "+$125,000", "description": "Enterprise contract — Acme Corp"},
                {"date": "2025-06-03", "amount": "-$45,000",  "description": "Infrastructure hosting costs"},
                {"date": "2025-06-05", "amount": "+$89,500",  "description": "Security consulting services"},
            ],
        },
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003)
