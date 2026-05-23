# Zero Trust Network Implementation
### SENG 473 — Information Security | Final Project

---

## Team Members

| Name | Student ID |
|---|---|
| Abdisamed Ahmed Mohamud | 230208709 |
| Suad Abdırahman | 220208783 |
| Manar Algburi | 220208935 |

---

## Architecture Overview

```
                    ┌─────────────────────────────────────────────────────┐
                    │               INTERNAL DOCKER NETWORK               │
  ┌──────────┐      │   ┌──────────────┐      ┌──────────────────┐        │
  │          │      │   │ Auth Service │      │  Policy Engine   │        │
  │  Browser │ ─────┼─► │  (port 5001) │      │  (port 5002)     │        │
  │          │      │   │              │      │                  │        │
  └──────────┘      │   │ • Login/JWT  │      │ • Role rules     │        │
        │           │   │ • Verify     │      │ • Device trust   │        │
        │           │   │ • Revoke     │      │ • Time windows   │        │
        ▼           │   └──────────────┘      └──────────────────┘        │
  ┌──────────────┐  │            ▲                      ▲                  │
  │              │  │            │                      │                  │
  │ API Gateway  │──┼────────────┘──────────────────────┘                  │
  │ (port 8080)  │  │                                                      │
  │              │  │   ┌──────────────────────────────┐                  │
  │ ① Verify JWT │  │   │     Resource Service         │                  │
  │ ② Eval Policy│──┼───► (port 5003)                  │                  │
  │ ③ Log access │  │   │                              │                  │
  │ ④ Serve UI   │  │   │ /public  /employee           │                  │
  └──────────────┘  │   │ /admin   /finance            │                  │
                    │   └──────────────────────────────┘                  │
                    └─────────────────────────────────────────────────────┘

  ONLY the API Gateway (port 8080) is exposed to the host.
  All other services are on an internal-only Docker network.
```

---

## Zero Trust Principles Implemented

| Principle | Implementation |
|---|---|
| **Never Trust, Always Verify** | Every request re-verified — no session cookies |
| **Least Privilege** | Role-based access: viewer < employee < admin |
| **Assume Breach** | Short-lived JWTs (2 min), token revocation |
| **Device Trust** | Device fingerprint registered on login; required for sensitive resources |
| **Continuous Monitoring** | Full audit log of every allow/deny decision |
| **Micro-segmentation** | Internal services isolated on Docker internal network |
| **Time-based Controls** | Finance endpoint restricted to business hours |

---

## Demo Users

| Username | Password | Role | Can Access |
|---|---|---|---|
| `admin` | `Admin@123` | admin | All resources |
| `alice` | `Alice@123` | employee | public, employee |
| `bob` | `Bob@123` | employee | public, employee |
| `charlie` | `Charlie@123` | viewer | public only |

---

## Quick Start

### Prerequisites
- Docker Desktop (or Docker + Docker Compose)
- Git (optional)

### Run the Project

```bash
# 1. Navigate to the project folder
cd zero-trust

# 2. Build and start all services
docker compose up --build

# 3. Open the dashboard
# http://localhost:8080
```

### Stop the Project

```bash
docker compose down
```

---

## Video Walkthrough Outline (SENG 473 Submission)

### Part 1 — Code Walkthrough (~5 min)

1. **Architecture overview** — show `docker-compose.yml`, explain the two networks
2. **Auth Service** (`auth-service/app.py`)
   - How credentials are verified (bcrypt)
   - JWT structure: sub, role, device_id, jti, exp
   - Token revocation via JTI blacklist
3. **Policy Engine** (`policy-engine/app.py`)
   - The POLICIES dict: roles, device trust, time windows
   - Risk score calculation
4. **API Gateway** (`api-gateway/app.py`)
   - The 5-step enforcement flow (verify → evaluate → fetch → log → return)
   - How each step maps to a Zero Trust principle

### Part 2 — Live Demo (~5 min)

1. **Start the system** — `docker compose up`, show 4 containers healthy
2. **Login as charlie (viewer)**
   - Access Public ✅
   - Access Employee ❌ — "Role viewer not permitted"
   - Access Admin ❌
3. **Login as alice (employee)**
   - Access Employee ✅
   - Access Admin ❌ — "Role employee not permitted"
4. **Login as admin**
   - Access Admin ✅ — show ZT metadata (policy, risk score, device trusted)
   - Access Finance ✅
   - Show audit log with full history
5. **Token expiry demo**
   - Watch the 2-minute countdown hit zero
   - Try to access a resource — show "Token expired" 401
6. **Show Docker network** — `docker network ls` + `docker inspect` to prove internal services have no host port mapping

---

## File Structure

```
zero-trust/
├── docker-compose.yml          ← Orchestration + network isolation
├── README.md
├── auth-service/
│   ├── app.py                  ← JWT auth, bcrypt, device trust, revocation
│   ├── requirements.txt
│   └── Dockerfile
├── policy-engine/
│   ├── app.py                  ← Zero Trust policies + risk scoring
│   ├── requirements.txt
│   └── Dockerfile
├── resource-service/
│   ├── app.py                  ← Protected data endpoints
│   ├── requirements.txt
│   └── Dockerfile
└── api-gateway/
    ├── app.py                  ← Enforcement point + audit log + UI server
    ├── requirements.txt
    ├── Dockerfile
    └── templates/
        └── index.html          ← Dashboard (Bootstrap 5, dark theme)
```
