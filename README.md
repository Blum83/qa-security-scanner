# QA Security Scanner

A web application that allows QA engineers to scan websites for security vulnerabilities and receive human-readable reports — no security expertise required.

![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104-green.svg)
![React 19](https://img.shields.io/badge/react-19-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- **Security Header Analysis** — checks for missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, cookie flags, HTTPS enforcement)
- **SSL/TLS Audit** — certificate expiry, chain of trust, TLS 1.0/1.1 detection, weak cipher detection
- **OWASP ZAP Scan** — automated spider for URL discovery + vulnerability detection
- **Nuclei CVE Scan** — fast template-based vulnerability scanning for known CVEs
- **Plain-Language Reports** — results translated into understandable explanations with actionable recommendations
- **PDF Report Export** — download professional PDF reports for sharing with your team
- **Scheduled Scans** — set up recurring scans with cron expressions and receive notifications via Slack or email
- **Scan History** — view all past scans with risk summaries and click through to detailed reports

## Quick Start

```bash
docker-compose up --build
```

Then open **http://localhost:5173** in your browser.

| Service | URL |
|---------|-----|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:8000 |
| Swagger UI | http://localhost:8000/docs |
| ZAP API | http://localhost:8080 |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, FastAPI, httpx, Pydantic, APScheduler |
| Frontend | React 19, Vite, Axios, React Router v7 |
| Security | OWASP ZAP, Nuclei |
| Infrastructure | Docker, docker-compose |
| Persistence | SQLite (scans + schedules) |

## Scan Flow

1. **Enter a URL** — the frontend auto-adds `https://` if missing
2. **The system runs security checks in phases:**
   - **Phase 1 (2–10%):** Security header analysis
   - **Phase 1.5 (10–15%):** SSL/TLS audit
   - **Phase 2 (15–92%):** ZAP Spider + Nuclei CVE scan (run in parallel)
   - **Phase 3 (92–100%):** Collect results, build report
3. **Review results** — issues are grouped by risk level (Critical, High, Medium, Low, Info) with plain-language explanations and fix recommendations
4. **Export** — download a PDF report or view scan history

> **Note:** ZAP active scan is disabled by default (too slow, many false positives). The scanner focuses on spider-based URL discovery + Nuclei for fast, reliable results.

## Scheduled Scans

Set up recurring security scans with cron expressions:

- **Cron format:** standard 5-field UTC (e.g., `0 9 * * 1` = every Monday at 9:00 UTC)
- **Notifications:** receive results via Slack (incoming webhook with Block Kit) or email (SMTP)
- **Persistence:** schedules stored in SQLite, survive restarts
- **Management:** create, update, pause, resume, and delete schedules from the UI

## API Reference

Interactive API documentation (Swagger UI) is available at **http://localhost:8000/docs** when the backend is running.

### Scan Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan` | Start a new scan |
| `GET` | `/scan` | List all scans with summaries |
| `GET` | `/scan/{scan_id}` | Get scan status and results |
| `POST` | `/scan/{scan_id}/stop` | Cancel a running scan |
| `GET` | `/scan/{scan_id}/pdf` | Download PDF report |

### Schedule Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/schedules` | Create a new schedule |
| `GET` | `/schedules` | List all schedules |
| `GET` | `/schedules/{id}` | Get schedule details + next run time |
| `PUT` | `/schedules/{id}` | Update a schedule |
| `DELETE` | `/schedules/{id}` | Soft-delete a schedule |
| `POST` | `/schedules/{id}/pause` | Pause a schedule |
| `POST` | `/schedules/{id}/resume` | Resume a schedule |

### Health Check

```
GET /health
```

Returns ZAP and Nuclei status.

### Example: Start a Scan

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

Response:
```json
{
  "scan_id": "uuid",
  "status": "pending"
}
```

### Example: Get Scan Results

```bash
curl http://localhost:8000/scan/{scan_id}
```

Response:
```json
{
  "scan_id": "uuid",
  "status": "completed",
  "target_url": "https://example.com",
  "progress": 100,
  "summary": { "critical": 0, "high": 2, "medium": 3, "low": 1, "info": 0 },
  "issues": [
    {
      "type": "header",
      "name": "Missing Content Security Policy",
      "risk": "high",
      "message": "Human-readable explanation...",
      "recommendation": "Clear fix suggestion...",
      "url": "https://example.com"
    }
  ]
}
```

## Project Structure

```
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app, CORS, router mount, APScheduler lifespan
│   │   ├── core/
│   │   │   ├── config.py        # Settings (ZAP URL, CORS, timeouts, SMTP)
│   │   │   ├── store.py         # SQLite-backed scan store
│   │   │   └── schedule_store.py # SQLite-backed schedule store
│   │   ├── models/
│   │   │   ├── scan.py          # Pydantic schemas for scans
│   │   │   └── schedule.py      # Pydantic schemas for schedules
│   │   ├── routes/
│   │   │   ├── scans.py         # Scan API endpoints
│   │   │   └── schedules.py     # Schedule CRUD endpoints
│   │   ├── services/
│   │   │   ├── scanner.py       # Scan orchestrator (headers → SSL → ZAP + Nuclei → report)
│   │   │   ├── header_checker.py # Security header analysis
│   │   │   ├── ssl_auditor.py   # SSL/TLS audit (cert expiry, weak TLS, ciphers)
│   │   │   ├── zap_scanner.py   # ZAP API integration (spider, risk mapping, dedup)
│   │   │   ├── nuclei_scanner.py # Nuclei CLI integration for CVE detection
│   │   │   ├── scheduler.py     # APScheduler AsyncIOScheduler wrapper
│   │   │   ├── notifier.py      # Slack + email notifications
│   │   │   └── pdf_report.py    # PDF report generation
│   │   └── utils/
│   │       ├── ssrf_protection.py # SSRF protection utilities
│   │       └── url_priority.py  # URL prioritization for scanning
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx              # Route shell + scan state machine
│   │   ├── api.js               # Axios API client
│   │   ├── components/
│   │   │   ├── Navbar.jsx       # Navigation with History + Schedules links
│   │   │   ├── Hero.jsx         # Landing hero section
│   │   │   ├── Features.jsx     # Feature cards
│   │   │   ├── ScanForm.jsx     # URL input form
│   │   │   ├── ScanProgress.jsx # Live progress bar + phase tracking
│   │   │   ├── ScanReport.jsx   # Results with summary cards + PDF download
│   │   │   ├── ScanDashboard.jsx # Scan history with stats
│   │   │   └── ScheduleManager.jsx # Schedule CRUD + pause/resume
│   │   └── assets/
│   ├── Dockerfile
│   └── package.json
├── docker-compose.yml
├── .env.example
└── README.md
```

## Environment Variables

Copy `.env.example` to `.env` and adjust values as needed:

```bash
cp .env.example .env
```

| Variable | Description | Default |
|----------|-------------|---------|
| `QA_SCANNER_ZAP_BASE_URL` | URL of the OWASP ZAP instance | `http://zap:8080` |
| `QA_SCANNER_ZAP_API_KEY` | ZAP API key (leave empty if disabled) | *(empty)* |
| `QA_SCANNER_CORS_ORIGINS` | Comma-separated list of allowed origins | `["http://localhost:5173","http://localhost:3000"]` |
| `QA_SCANNER_SCAN_TIMEOUT_SECONDS` | General scan timeout | `600` |
| `QA_SCANNER_ZAP_SCAN_TIMEOUT_SECONDS` | ZAP scan timeout | `600` |
| `QA_SCANNER_ZAP_ACTIVE_SCAN_TIMEOUT_SECONDS` | ZAP active scan timeout | `600` |
| `QA_SCANNER_NUCLEI_SCAN_TIMEOUT_SECONDS` | Nuclei scan timeout | `120` |
| `QA_SCANNER_NUCLEI_RATE_LIMIT` | Nuclei rate limit (requests/sec) | `150` |
| `QA_SCANNER_NUCLEI_TIMEOUT` | Nuclei request timeout (seconds) | `10` |
| `QA_SCANNER_NUCLEI_SEVERITIES` | Nuclei severity levels to report | `["critical","high","medium","low"]` |
| `QA_SCANNER_ZAP_MAX_DEPTH` | Maximum crawl depth | `3` |
| `QA_SCANNER_ZAP_THREAD_COUNT` | Number of scan threads | `10` |
| `QA_SCANNER_SMTP_HOST` | SMTP server host | — |
| `QA_SCANNER_SMTP_PORT` | SMTP server port | — |
| `QA_SCANNER_SMTP_USER` | SMTP username | — |
| `QA_SCANNER_SMTP_PASSWORD` | SMTP password | — |
| `QA_SCANNER_SMTP_FROM` | SMTP sender address | — |

## Running Without Docker

**Backend:**
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

**ZAP** (required for full scans):
```bash
docker run -p 8080:8080 zaproxy/zap-stable zap.sh -daemon \
  -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config api.disablekey=true
```

## Data Persistence

- **Scans and schedules:** SQLite at `backend/data/scans.db` — mounted as a Docker volume for persistence
- **Frontend state:** `localStorage` stores `currentScanId` for recovery on page reload

## Notes

- ZAP scans can take several minutes depending on the target site size
- If ZAP is not running, the scanner gracefully falls back to header-only checks
- Only scan sites you have permission to test
- All cron expressions use UTC timezone
- Webhook and notification failures are logged but do not affect scan status
