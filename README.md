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
