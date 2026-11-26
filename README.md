<div align="center">
  <img alt="TradeDesk logo" src="app/static/favicon.svg" width="80" />
</div>
<h1 align="center">TradeDesk</h1>
<p align="center">
  Job documentation for independent tradespeople, built with FastAPI and PostgreSQL
</p>
<p align="center">
  <a href="https://github.com/hmdevio/tradedesk/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/hmdevio/tradedesk/actions/workflows/ci.yml/badge.svg" /></a>
</p>

![TradeDesk sign-in screen](docs/images/dashboard.png)

TradeDesk keeps customers, jobs, trade-specific worksheets, sketches, service reports and follow-up tasks in one place, and produces a branded PDF report the customer can keep.

© PACCTECH LLC. All rights reserved. See [LICENSE](LICENSE).

## Features

- Accounts: registration with email verification, sign-in, password change and reset by emailed single-use link, and session renewal with a 12-hour absolute limit.
- Customers and jobs: create, edit and delete them; job status (New, In Progress, Completed, Cancelled) with an Open/All/status filter. Customers and jobs with an approved report are protected from deletion.
- Trade worksheets: worksheets for electricians, plumbers, HVAC technicians, carpenters, welders, and automotive and diesel mechanics.
- Sketches and photos: up to 10 per job, each with a subject. Uploads are validated and re-encoded, and location metadata is removed.
- Service reports: drafts in four sections, explicit approval, report history per job, and PDF export of approved reports only.
- Business profile: name, license number, contact details and logo, printed on every approved report.
- Follow-up tasks: due dates, completion and reopening, and an overdue indicator.

## Technology

| Layer | Stack |
|---|---|
| API | Python 3.13, FastAPI, Pydantic 2, Uvicorn |
| Data | SQLAlchemy 2, Alembic, PostgreSQL 18 (mutual TLS); SQLite for tests |
| Security | Argon2 (pwdlib), JWT bound to server-side sessions, Redis rate limiting |
| Documents | ReportLab (PDF), Pillow (image processing) |
| Frontend | HTML, CSS and JavaScript with no build step and no third-party scripts |
| Tests | pytest with FastAPI `TestClient` |

## Getting started

Requires Python 3.13 (3.11 or newer works) and, for anything beyond tests, PostgreSQL.

```powershell
git clone https://github.com/hmdevio/tradedesk.git
cd tradedesk
py -3.13 -m venv .venv313
.\.venv313\Scripts\python -m pip install --upgrade pip
.\.venv313\Scripts\python -m pip install --require-hashes -r requirements-lock.txt
Copy-Item .env.example .env
```

On macOS or Linux, use `python3 -m venv .venv`, `source .venv/bin/activate` and `cp .env.example .env`.

Edit `.env` and set at least `ENVIRONMENT` and `SECRET_KEY` (see [Configuration](#configuration)). Then start the server:

```powershell
.\.venv313\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open http://127.0.0.1:8000. Interactive API docs are at `/docs` outside production.

For PostgreSQL, set `DATABASE_URL` and the `DATABASE_SSL*` values in `.env`, then apply the migrations with `.\.venv313\Scripts\python -m alembic upgrade head`.

## Configuration

Settings come from environment variables or a local `.env` file. `.env` is never committed. The app refuses to start when a required setting is missing or unsafe.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `ENVIRONMENT` | yes | none | `development`, `test` or `production` |
| `SECRET_KEY` | yes | none | At least 32 random characters. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `DATABASE_URL` | for PostgreSQL | `sqlite:///./tradedesk.db` | For example `postgresql+psycopg://USER:PASSWORD@localhost:5432/DBNAME` |
| `DATABASE_SSLMODE`, `DATABASE_SSLROOTCERT`, `DATABASE_SSLCERT`, `DATABASE_SSLKEY` | PostgreSQL | `verify-full` | TLS mode, CA certificate, and client certificate and key |
| `REDIS_URL` | production | empty | Rate-limit store. Production requires `rediss://` with a password; without it, rate limiting is off and a warning is logged |
| `TRUSTED_PROXY_CIDRS` | no | empty | Proxies whose `X-Forwarded-For` header is trusted |
| `CORS_ORIGINS` | no | empty | Comma-separated browser origins; the bundled UI needs none |
| `ACCESS_TOKEN_MINUTES` | no | 30 | Access token lifetime |
| `SESSION_MAX_HOURS` | no | 12 | Absolute session limit after sign-in |
| `APP_BASE_URL` | production | `http://localhost:8000` | Base for email links; must be HTTPS in production |
| `EMAIL_VERIFICATION_MINUTES`, `PASSWORD_RESET_MINUTES` | no | 30 | Email link lifetimes |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`, `SMTP_USE_STARTTLS`, `SMTP_USE_SSL` | production | port 587, STARTTLS | Email delivery. Credentials are only sent over TLS |

## Tests

```powershell
.\.venv313\Scripts\python -m pytest -q
```

The suite uses a temporary SQLite database and needs no PostgreSQL, Redis or SMTP server. CI runs it on every pull request, together with pip-audit and Bandit.

## API overview

All endpoints except authentication, `/health` and the static UI require `Authorization: Bearer <token>`. Records are scoped to the signed-in account; another account's IDs return 404. List endpoints accept `?limit=` (1 to 200, default 100) and `?offset=`.

| Area | Endpoints |
|---|---|
| Authentication | `POST /auth/register`, `/auth/verify-email`, `/auth/resend-verification`, `/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/password`, `/auth/forgot-password`, `/auth/reset-password` |
| Customers | `GET/POST /customers`, `GET/PATCH/DELETE /customers/{id}`, `GET /customers/{id}/impact` |
| Jobs | `GET/POST /jobs`, `GET/PATCH/DELETE /jobs/{id}`, `GET /jobs/{id}/impact` |
| Reports | `POST /jobs/{id}/reports/draft`, `GET /jobs/{id}/reports`, `GET/PATCH /reports/{id}`, `POST /reports/{id}/approve`, `GET /reports/{id}/pdf` |
| Tasks | `GET/POST /jobs/{id}/tasks`, `PATCH/DELETE /tasks/{id}` |
| Worksheets | `GET /worksheet-templates`, `GET/PUT/DELETE /jobs/{id}/worksheet` |
| Sketches | `GET/POST /jobs/{id}/sketches`, `GET /sketches/{id}/image`, `DELETE /sketches/{id}` |
| Business profile | `GET/PUT /profile`, `GET/PUT/DELETE /profile/logo` |
| Health | `GET /health` |

Report content is a JSON object with the sections `work_performed`, `findings_observations`, `recommendations` and `suggested_follow_up`, each up to 5,000 characters. Approved reports can't be edited, and only approved reports can be exported.

## Project structure

```text
app/
  main.py            routes, middleware and business rules
  models.py          database tables
  schemas.py         request and response validation
  dependencies.py    authentication dependencies
  security.py        password hashing and tokens
  rate_limit.py      Redis rate limiting
  config.py          settings and startup validation
  database.py        engine and sessions
  reporting.py       report drafts and PDF layout
  worksheets.py      trade templates and image processing
  email_delivery.py  SMTP delivery
  fonts/             DejaVu Sans for PDFs (with license)
  static/            dashboard HTML, CSS and JavaScript
migrations/          Alembic revisions
tests/               pytest suite
docs/images/         README screenshot
```

## Security

Please report security issues privately through the repository's Security tab ("Report a vulnerability"), not in a public issue.

## Status

TradeDesk is a working MVP that runs locally on PostgreSQL. It has not yet been deployed publicly.
