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

4. Start the stack:

```bash
docker compose up --build
```

5. Run migrations:

```bash
docker compose exec api alembic -c apps/api/alembic.ini upgrade head
```

6. Open the UI at `http://localhost:5173`.

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
