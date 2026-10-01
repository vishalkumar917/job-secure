# Deployment

## Docker (recommended)

```bash
cp .env.example .env            # set SECRET_KEY, ADMIN_PASSWORD, POSTGRES_PASSWORD
docker compose up --build
```

* UI: <http://localhost:8080> (`FRONTEND_PORT`)
* API + OpenAPI docs: <http://localhost:8000/docs> (`BACKEND_PORT`)

Ports are bound to `127.0.0.1` only. If a port is unavailable (on Windows, Hyper-V can reserve ranges that
include 8080), set `FRONTEND_PORT`/`BACKEND_PORT` in `.env`.

| Service | Image | Notes |
|---|---|---|
| `postgres` | postgres:16-alpine | Data in volume `pgdata`. |
| `backend` | python:3.12-slim + Volatility 3 + yara-python | Non-root UID 10001, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, memory/PID limits. Volumes: `evidence` (/data), `symbols` (/symbols), `volcache` (Volatility symbol cache). Large uploads are spooled to `/data/tmp`, not RAM. |
| `frontend` | nginx:1.27-alpine | Serves the built SPA, proxies `/api` to the backend with unlimited body size (the backend enforces `MAX_UPLOAD_BYTES`), CSP and security headers. |

### Symbols

Volatility downloads Windows symbol tables (ISF) on first use and caches them in the `volcache` volume.
For air-gapped analysis, copy symbol packs into the `symbols` volume and set `VOLATILITY_OFFLINE=true`.

### Using Ollama from Docker

```
AI_PROVIDER=ollama
AI_BASE_URL=http://host.docker.internal:11434
AI_MODEL=llama3.1:8b
```

(On Linux add `extra_hosts: ["host.docker.internal:host-gateway"]` to the backend service.)

## Local development

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1     # Windows
powershell -File scripts\run_dev.ps1
```

```bash
./scripts/setup.sh && ./scripts/run_dev.sh                       # Linux/macOS
```

Backend on <http://localhost:8000>, frontend on <http://localhost:5173> (Vite proxies `/api`).
SQLite database and evidence live in `backend/data/` (git-ignored).

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ENVIRONMENT` | development | `development` keeps raw plugin working files |
| `LOG_LEVEL` | INFO | Structured JSON log level |
| `CORS_ORIGINS` | `["http://localhost:5173","http://localhost:8080"]` | Allowed browser origins (JSON list) |
| `SECRET_KEY` | generated per start | JWT signing key - **set it**, otherwise sessions end on restart |
| `ACCESS_TOKEN_MINUTES` | 480 | Token lifetime |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | admin / ChangeMe!2026 | Seeded administrator (on first start only) - **change it** |
| `DATABASE_URL` | SQLite in `DATA_DIR` | e.g. `postgresql+psycopg://user:pass@host:5432/memtrace` |
| `DATA_DIR` | `backend/data` | Evidence, temp uploads, plugin outputs, reports, YARA uploads |
| `RULES_DIR`, `YARA_RULES_DIR`, `SAMPLE_DATA_DIR` | repo folders | Knowledge base locations |
| `MAX_UPLOAD_BYTES` | 34359738368 (32 GiB) | Upload limit |
| `MIN_IMAGE_BYTES` | 1048576 | Smaller files are rejected |
| `ALLOWED_EXTENSIONS` | .raw,.mem,.dmp,.vmem | Accepted formats |
| `VERIFY_HASH_ON_ANALYSIS` | true | Re-hash before/after analysis |
| `VOLATILITY_CMD` | auto | Explicit CLI command, e.g. `vol` or `python vol.py` |
| `VOLATILITY_SYMBOLS_DIR` | – | Extra symbol directory |
| `VOLATILITY_OFFLINE` | false | Never download symbols |
| `PLUGIN_TIMEOUT_SECONDS` | 900 | Per-plugin timeout |
| `ANALYSIS_WORKERS` | 1 | Concurrent analyses |
| `DEEP_SCAN_MAX_PIDS` | 15 | Triaged processes for targeted plugins |
| `ENABLE_FILESCAN` | false | Run windows.filescan |
| `YARA_SCAN_ALL_PROCESSES` | false | YARA-scan every process instead of triaged ones |
| `AI_PROVIDER` | deterministic | `deterministic`, `openai`, `ollama` |
| `AI_BASE_URL`, `AI_MODEL` | – | Provider endpoint and model |
| `AI_API_KEY` | – | Secret; env only, never stored or logged |
| `AI_TIMEOUT_SECONDS`, `AI_TEMPERATURE`, `AI_MAX_EVIDENCE_ITEMS` | 60, 0.1, 40 | LLM call tuning |
| `FRONTEND_PORT`, `BACKEND_PORT`, `BACKEND_MEM_LIMIT`, `POSTGRES_PASSWORD` | 8080, 8000, 8g, – | Docker only |

## Production hardening checklist

- [ ] Strong `SECRET_KEY`, `ADMIN_PASSWORD`, `POSTGRES_PASSWORD` in `.env` (never committed)
- [ ] TLS termination in front of nginx (reverse proxy or load balancer)
- [ ] Evidence volume on encrypted storage with backups and access auditing
- [ ] Restrict network egress of the backend (only symbol server / LLM endpoint if required)
- [ ] Prefer Ollama or the deterministic engine for sensitive cases
- [ ] Monitor structured logs (JSON on stdout)
