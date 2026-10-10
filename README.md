AppSentinel
===========

AppSentinel is a FastAPI and vanilla frontend app for correlating suspicious
messages, URLs, identities, and Android APK evidence. The backend stores scan
history with SQLAlchemy, uses SQLite for local development by default, and can
use hosted PostgreSQL in production through `DATABASE_URL`.

Project Layout
--------------

- `backend/` - FastAPI app, scan routes, analyzers, SQLAlchemy models.
- `frontend/` - static browser UI served by the backend or any static host.
- `tests/` - pytest/unittest coverage for API, analyzers, regressions, and config.
- `docker-compose.yml` - backend plus MobSF for containerized local or server runs.
- `docker/docker-compose.yml` - MobSF-only helper compose file.

Local Setup
-----------

1. Create and activate a Python virtual environment.
2. Install dependencies:

   ```powershell
   pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env` and fill only the keys you actually have:

   ```powershell
   Copy-Item .env.example .env
   ```

4. Start the backend:

   ```powershell
   python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
   ```

5. Open `http://localhost:8000` or serve `frontend/` separately and set
   `FRONTEND_ORIGIN` / `CORS_ORIGINS` as needed.

Database Configuration
----------------------

Local development defaults to:

```env
DATABASE_URL=sqlite:///./storage/appsentinel.db
```

For production, use a hosted PostgreSQL URL:

```env
DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DB_NAME
```

The backend normalizes common `postgres://` and `postgresql://` URLs to the
`psycopg` SQLAlchemy driver. SQLite file paths are resolved relative to the
project root so local runs and test runs do not depend on the shell's current
directory.

Docker
------

The root compose file runs both the AppSentinel API and MobSF:

```powershell
docker compose up --build
```

Inside that compose network, the backend uses:

```env
MOBSF_URL=http://mobsf:8000
```

For a local hackathon demo, `docker-compose.yml` provides a fallback
`MOBSF_API_KEY` so MobSF can boot even if `.env` is blank. For any public
deployment, set a strong `MOBSF_API_KEY` in the deployment environment and keep
`.env` out of Git.

For a hosted deployment, MobSF must run on infrastructure that supports Docker
containers with enough memory and persistent storage. A laptop Docker container
will not keep a hosted website's MobSF integration online.

External Services
-----------------

These integrations are optional and degrade gracefully when unset:

- `GEMINI_API_KEY` for AI explanations.
- `VIRUSTOTAL_API_KEY` for VirusTotal reputation checks.
- `URLSCAN_API_KEY` for urlscan.io lookups.
- `GOOGLE_SAFE_BROWSING_API_KEY` if Safe Browsing support is enabled.
- `MOBSF_API_KEY` for MobSF APK analysis.

Do not commit `.env`, local databases, scan uploads, or generated reports. The
included `.gitignore` and `.dockerignore` are set up for that.

Verification
------------

Run the test suite with:

```powershell
pytest
```

Before publishing or deploying, verify:

- `/api/health` reports the database online.
- A message scan saves and appears in `/api/scans`.
- PostgreSQL saves and retrieves scan history when `DATABASE_URL` points to the
  hosted database.
- MobSF is reachable from the backend by service name or public URL.
- Missing external credentials are shown as unavailable or unconfigured, never
  as fake successful results.
