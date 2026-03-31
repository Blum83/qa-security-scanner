# QA Security Scanner

Web-app for QA engineers to scan websites for security vulnerabilities and get human-readable reports.

## Architecture

**Monorepo: frontend + backend + OWASP ZAP + Nuclei**

```
frontend/   — React 19 + Vite, Axios, React Router v7 (URL routing + state-driven scan flow)
backend/    — Python 3.11 + FastAPI, httpx, Pydantic, APScheduler
ZAP         — OWASP ZAP daemon in Docker (spider + active scan)
Nuclei      — Fast CVE scanner (runs in backend container)
```

All services orchestrated via `docker-compose.yml`.

## Key URLs (local dev)

| Service        | URL                        |
|----------------|----------------------------|
| Frontend       | http://localhost:5173      |
| Backend API    | http://localhost:8000      |
| Swagger UI     | http://localhost:8000/docs |
| ZAP API        | http://localhost:8080      |

## Backend structure (`backend/app/`)

- `main.py` — FastAPI app, CORS, router mount, APScheduler lifespan (start/stop)
- `routes/scans.py` — scan API endpoints
- `routes/schedules.py` — schedule CRUD endpoints (create, list, update, delete, pause, resume)
- `services/scanner.py` — scan orchestrator (headers → SSL → ZAP spider + Nuclei in parallel → report)
- `services/header_checker.py` — checks CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, cookies, HTTPS
- `services/ssl_auditor.py` — SSL/TLS audit (cert expiry, chain of trust, TLS 1.0/1.1, weak ciphers) using stdlib ssl+socket
- `services/nuclei_scanner.py` — Nuclei CLI integration for fast CVE detection
- `services/zap_scanner.py` — ZAP API integration (spider + active scan, risk mapping, alert dedup)
- `services/scheduler.py` — APScheduler AsyncIOScheduler wrapper; re-registers active schedules from DB on startup
- `services/notifier.py` — Slack (Block Kit webhook) and email (smtplib) notifications after scheduled scans
- `models/scan.py` — Pydantic schemas (ScanRequest, ScanResponse, ScanReport, ScanRecord, enums)
- `models/schedule.py` — Pydantic schemas (ScheduleRequest, ScheduleResponse, ScheduleRecord, WebhookConfig)
- `core/config.py` — settings (zap_base_url, cors_origins, scan_timeout_seconds=600, nuclei settings, SMTP settings)
- `core/store.py` — SQLite-backed scan store (`data/scans.db`, survives restarts)
- `core/schedule_store.py` — SQLite-backed schedule store (same `data/scans.db`, table `schedules`)

## Frontend structure (`frontend/src/`)

- `App.jsx` — route shell (React Router) + scan state machine: "form" → "scanning" → "report". Polls GET /scan/{id} every 5s
- `api.js` — Axios client (baseURL: http://localhost:8000); scan + schedule API functions
- `components/Navbar.jsx` — header with NavLink (History→/history, Schedules→/schedules), logo Link→/, API Docs in new tab
- `components/Hero.jsx` — landing hero section
- `components/ScanForm.jsx` — URL input (auto-adds https://)
- `components/ScanProgress.jsx` — live progress bar, phase tracking, elapsed time, stop button
- `components/ScanReport.jsx` — results: summary cards + issues grouped by risk + PDF download
- `components/ScanDashboard.jsx` — scan history: stats (total/completed/issues/critical/high) + list of all scans with risk pills, click to open report
- `components/ScheduleManager.jsx` — schedule list, create form (cron + webhook config), pause/resume/delete
- `components/Features.jsx` — feature cards section

## API endpoints

| Method | Path                        | Purpose                              |
|--------|-----------------------------|--------------------------------------|
| POST   | /scan                       | Start scan (body: {url})             |
| GET    | /scan/{scan_id}             | Poll status & results                |
| POST   | /scan/{scan_id}/stop        | Cancel running scan                  |
| GET    | /scan/{scan_id}/pdf         | Download PDF report                  |
| GET    | /scan                       | List all scans with summaries        |
| GET    | /health                     | Health check (ZAP + Nuclei status)   |
| POST   | /schedules                  | Create schedule                      |
| GET    | /schedules                  | List all schedules                   |
| GET    | /schedules/{id}             | Get schedule detail + next_run_at    |
| PUT    | /schedules/{id}             | Update schedule                      |
| DELETE | /schedules/{id}             | Soft-delete schedule                 |
| POST   | /schedules/{id}/pause       | Pause schedule                       |
| POST   | /schedules/{id}/resume      | Resume schedule                      |

## Scan flow

1. User submits URL → POST /scan → returns scan_id
2. Frontend polls GET /scan/{id} every 5s
3. Backend pipeline:
   - Phase 1 (2–10%): Security header analysis (CSP, HSTS, X-Frame-Options, cookies…)
   - Phase 1.5 (10–15%): SSL/TLS audit (cert expiry, weak TLS versions, weak ciphers)
   - Phase 2 (15–92%): ZAP Spider + Nuclei CVE scan run in parallel
   - Phase 3 (92–100%): Collect results, build report
4. ZAP active scan skipped (too slow, many false positives)
5. Results: issues with type (header/ssl/nuclei/zap), risk level, plain-language message, recommendation

## Scheduled scans

- Schedules stored in SQLite, survive restarts
- APScheduler uses `AsyncIOScheduler` (same event loop as FastAPI/uvicorn)
- On startup, `start_scheduler()` re-registers all `ACTIVE` schedules from DB
- Cron expressions: standard 5-field UTC (e.g. `0 9 * * 1` = every Monday 9am)
- Notifications: Slack incoming webhook (Block Kit) or SMTP email
- SMTP configured via env vars: `QA_SCANNER_SMTP_HOST`, `QA_SCANNER_SMTP_PORT`, `QA_SCANNER_SMTP_USER`, `QA_SCANNER_SMTP_PASSWORD`, `QA_SCANNER_SMTP_FROM`

## Data persistence

- Scans and schedules: SQLite at `backend/data/` (`scans.db`) — mounted as Docker volume
- Frontend: `localStorage` stores `currentScanId` for recovery on page reload

## Commands

```bash
# Full stack
docker-compose up --build

# Backend only
cd backend && pip install -r requirements.txt && uvicorn app.main:app --reload

# Frontend only
cd frontend && npm install && npm run dev
```

## Conventions

- CSS: component-scoped files (Component.css), CSS variables for theming (--bg-nav, etc.)
- React Router v7: `/` (scan flow), `/history`, `/schedules` — logo and nav links use `Link`/`NavLink`
- Scan flow (form → scanning → report) remains state-driven within the `/` route
- Backend uses async/await throughout
- Pydantic models for all request/response schemas
- Synchronous blocking operations (ssl probes, smtplib) run in `asyncio.run_in_executor`
- Webhook/notification failures are always swallowed (logged only) — must not affect scan status
