# Zero Trust Network Implementation

This project runs a Zero Trust demo with four services:
- `auth-service` (JWT auth, login, verify, logout)
- `policy-engine` (policy decision engine)
- `resource-service` (protected endpoints)
- `api-gateway` (external gateway, dashboard, enforcement)

## Run the project

```bash
cd zero-trust
docker compose up --build
```

Open the UI at:

```bash
http://localhost:8080
```

## Demo users

- `admin` / `Admin@123`
- `alice` / `Alice@123`
- `bob` / `Bob@123`
- `charlie` / `Charlie@123`
