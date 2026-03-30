# QA Security Scanner

A web application that allows QA engineers to scan websites and receive human-readable security reports — no security expertise required.

## What It Does

1. Enter a website URL
2. The system runs security checks:
   - **Header analysis** — checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.)
   - **OWASP ZAP scan** — automated spider + active scan for vulnerabilities (XSS, SQL injection, etc.)
3. Results are translated into plain-language explanations with actionable recommendations

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, FastAPI, httpx, Pydantic |
| Frontend | React (Vite), Axios |
| Security | OWASP ZAP (Docker) |
| Infrastructure | Docker, docker-compose |

## Quick Start

```bash
docker-compose up --build
```

Then open **http://localhost:5173** in your browser.

| Service | URL |
|---------|-----|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:8000 |
| ZAP API | http://localhost:8080 |

## API Reference

Interactive API documentation (Swagger UI) is available at **http://localhost:8000/docs** when the backend is running.

### Start a Scan

```
POST http://localhost:8000/scan
Content-Type: application/json

{ "url": "https://example.com" }
```

Response:
```json
{ "scan_id": "uuid", "status": "pending" }
```

### Get Scan Results

```
GET http://localhost:8000/scan/{scan_id}
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

### Stop a Scan

```
POST http://localhost:8000/scan/{scan_id}/stop
```

Response:
```json
{ "scan_id": "uuid", "status": "cancelled" }
```

### Health Check

```
GET http://localhost:8000/health
```

## Project Structure

```
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI app + CORS
│   │   ├── core/            # Config, in-memory store
│   │   ├── models/          # Pydantic schemas
│   │   ├── routes/          # API endpoints
│   │   ├── services/        # Scanner, header checker, ZAP integration
│   │   └── utils/
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/      # ScanForm, ScanProgress, ScanReport
│   │   ├── api.js           # Axios API client
│   │   └── App.jsx          # Main app with state management
│   ├── Dockerfile
│   └── package.json
├── docker-compose.yml
└── README.md
```

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
docker run -p 8080:8080 zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.disablekey=true
```

## Notes

- ZAP scans can take several minutes depending on the target site
- If ZAP is not running, the scanner gracefully falls back to header-only checks
- Scan results are stored in memory (MVP) — they are lost on backend restart
- Only scan sites you have permission to test
