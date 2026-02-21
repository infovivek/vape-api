# Authorized API VAPT Scanner

Authorized API VAPT Scanner is a safety-first web application for ethical API testing. **Use only on assets you own or have written permission to test.**

## Setup

### Local dev (Docker)

1. Copy environment defaults:

```bash
cp .env.example .env
```

2. Generate an encryption key (required for API key storage):

```bash
python scripts/generate_key.py
```

3. Paste the generated key into `.env` as `VAPT_ENCRYPTION_KEY`.

4. Generate an API key salt (required for SaaS API keys):

```bash
python - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
```

5. Paste the generated value into `.env` as `VAPT_API_KEY_SALT`.

6. Start the stack:

```bash
docker compose up --build
```

7. Run migrations:

```bash
docker compose exec api alembic -c apps/api/alembic.ini upgrade head
```

8. Open the UI at `http://localhost:5173`.

## Using the app (step-by-step)

1. Register a tenant admin account from the UI (Register section).
2. Create a project name under “Projects.”
3. Add a target:
   - Base URL (must match allowlisted host)
   - Allowlisted hosts (comma-separated)
   - Optional API key header/name
   - Authorization text or owner attestation
4. Start a scan from the target list.
5. Enter the scan ID in “Download Report” to view the HTML report.
6. (Optional) Generate an API key from the “API Keys” section for programmatic access.
7. Scan results remain visible for 7 days in the UI and API; historical data is retained in the database for audit needs.

## Safe-use policy

- Scans require proof of authorization (attestation or uploaded authorization text).
- Allowlisted hosts are mandatory, and SSRF to private ranges is blocked by default.
- Rate-limit checks are bounded at 60 requests/minute per host with a burst of 10.
- The scanner stops if it detects 429/503 spikes or latency anomalies.
- No DoS, brute force, or availability-degrading techniques are implemented.

## Threat model (short)

- **Assets:** API credentials, project scopes, scan results.
- **Threats:** Unauthorized scans, SSRF abuse, credential leakage.
- **Controls:** JWT + optional TOTP, RBAC, encrypted API keys at rest, allowlist enforcement, and redacted evidence in reports.

## How to add new checks

1. Add a method to `packages/shared/shared/scanner.py` and call it from `_run_checks`.
2. Ensure the check is safe (no time-based or high-volume probes).
3. Add a unit test in `packages/shared/tests/`.
4. Update report template as needed.

## Demo run script

```bash
python scripts/demo_run.py
```

The demo uses the sample OpenAPI/Postman files under `samples/` and generates `demo-report.html`.

## AWS SaaS deployment guide (recommended baseline)

This application is ready to run as a multi-tenant SaaS. Users can self-register, generate an API key, and launch scans from the UI.

### Architecture (production-friendly)

- **Web**: S3 + CloudFront (static build from `apps/web`)
- **API**: ECS Fargate service behind an ALB
- **Worker**: ECS Fargate service (no public ingress)
- **Database**: Amazon RDS for PostgreSQL
- **Queue/Cache**: Amazon ElastiCache for Redis
- **Secrets**: AWS Secrets Manager or SSM Parameter Store
- **Logs**: CloudWatch Logs

### Step-by-step AWS setup (high level)

1. **Provision data stores**
   - Create an RDS Postgres instance.
   - Create an ElastiCache Redis cluster.
2. **Create secrets**
   - `VAPT_JWT_SECRET`, `VAPT_ENCRYPTION_KEY`, `VAPT_API_KEY_SALT` must be generated and stored securely.
3. **Build and push images**
   - Build `apps/api` and `apps/worker` Docker images.
   - Push to ECR repositories.
4. **Create ECS services**
   - **API service** with an ALB listener (port 8000).
   - **Worker service** without public access.
5. **Configure environment variables**
   - Use the same env values as `.env.example`, plus production endpoints for Postgres/Redis and the correct `VAPT_CORS_ORIGINS` value for your web domain.
6. **Run migrations**
   - Run `alembic upgrade head` against the RDS database.
7. **Deploy the web UI**
   - Build `apps/web` using `VITE_API_BASE` pointing at the ALB.
   - Upload the build output to S3 and serve through CloudFront.

### Free signup + API keys

- Users can **register from the UI** and immediately access their tenant.
- From “API Keys,” they can **generate an API key** for programmatic access.
- API keys are **hashed at rest** and displayed only once on creation.
- For API access, send the key in the `X-API-Key` header.
