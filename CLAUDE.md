# QA Security Scanner

Web-app for QA engineers to scan websites for security vulnerabilities and get human-readable reports.

## Architecture

**Monorepo: frontend + backend + OWASP ZAP + Nuclei**

```
frontend/   — React 19 + Vite, Axios (SPA, no router — state-driven views)
backend/    — Python 3.11 + FastAPI, httpx, Pydantic
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

- `main.py` — FastAPI app, CORS, router mount
- `routes/scans.py` — API endpoints (POST /scan, GET /scan/{id}, POST /scan/{id}/stop, GET /health)
- `services/scanner.py` — scan orchestrator (header check → Nuclei + ZAP spider in parallel → ZAP active scan → report)
- `services/header_checker.py` — checks CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, cookies, HTTPS
- `services/nuclei_scanner.py` — Nuclei CLI integration for fast CVE detection
- `services/zap_scanner.py` — ZAP API integration (spider + active scan, risk mapping, alert dedup)
- `models/scan.py` — Pydantic schemas (ScanRequest, ScanResponse, ScanReport, ScanRecord, enums)
- `core/config.py` — settings (zap_base_url, cors_origins, scan_timeout_seconds=600, nuclei settings)
- `core/store.py` — in-memory dict store (MVP, lost on restart)

## Frontend structure (`frontend/src/`)

- `App.jsx` — main state machine: "form" → "scanning" → "report". Polls GET /scan/{id} every 3s
- `api.js` — Axios client (baseURL: http://localhost:8000)
- `components/Navbar.jsx` — header with API Docs link
- `components/Hero.jsx` — landing hero section
- `components/ScanForm.jsx` — URL input (auto-adds https://)
- `components/ScanProgress.jsx` — live progress bar, phase tracking, elapsed time, stop button
- `components/ScanReport.jsx` — results: summary cards + issues grouped by risk
- `components/Features.jsx` — feature cards section

## API endpoints

| Method | Path               | Purpose                    |
|--------|--------------------|----------------------------|
| POST   | /scan              | Start scan (body: {url})   |
| GET    | /scan/{scan_id}    | Poll status & results      |
| POST   | /scan/{scan_id}/stop | Cancel running scan       |
| GET    | /health            | Health check               |

## Scan flow

1. User submits URL → POST /scan → returns scan_id
2. Frontend polls GET /scan/{id} every 5s
3. Backend pipeline: header analysis (2%) → ZAP Spider (crawl) → Nuclei CVE scan (detect) → build report
4. ZAP Spider discovers URLs (~5min), Nuclei checks for known CVEs (~30s)
5. ZAP active scan skipped (too slow, many false positives)
6. Results: issues with type (header/nuclei/zap), risk level, plain-language message, recommendation

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
- No React Router — single-page state machine in App.jsx
- Backend uses async/await throughout
- Pydantic models for all request/response schemas
