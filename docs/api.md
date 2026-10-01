# REST API

Interactive OpenAPI documentation is served by the backend at **`/docs`** (Swagger UI) and **`/redoc`**.
All endpoints except `/api/health` and `/api/auth/login` require `Authorization: Bearer <JWT>`.
Errors are returned as `{"detail": "<human-readable message>"}` with an appropriate status code
(401, 403, 404, 409, 413, 422, 429, 502, 503).

Endpoints scoped to one analysis take `analysis_id` as a query parameter.

## Authentication

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/login` | `{"username","password"}` → `{"access_token","token_type","user"}`. 5 failures per (IP, user) in 5 min → 429. |
| GET | `/api/auth/me` | Current user. |

## Cases and evidence

| Method | Path | Description |
|---|---|---|
| POST | `/api/cases` | Create case `{"title","description","case_number?"}`. Records `case_opened`. |
| GET | `/api/cases` | List cases. |
| GET | `/api/cases/{id}` | Case with images and analyses. |
| PATCH | `/api/cases/{id}` | Update title/description/status (`open`/`closed`). |
| GET | `/api/cases/{id}/custody` | Chain-of-custody events. |
| POST | `/api/memory/upload` | multipart `case_id`, `file` (.raw/.mem/.dmp/.vmem). Streams, hashes (SHA-256), validates, stores read-only. 413 if too large, 422 if invalid. |
| GET | `/api/memory?case_id=` | List images. |
| GET | `/api/memory/{id}` | Image metadata incl. SHA-256 and OS identification. |
| POST | `/api/memory/{id}/verify` | Re-hash and compare with the intake hash (custody event). |

## Analysis

| Method | Path | Description |
|---|---|---|
| POST | `/api/analysis/{image_id}/start` | `{"yara": true}` → job (202). 503 if Volatility is missing; 409 if already running. |
| GET | `/api/analysis` | Recent jobs. |
| GET | `/api/analysis/{job_id}/status` | Status, stage, progress, integrity flags, error. |
| GET | `/api/analysis/{job_id}` | Job detail with summary counts, image and case. |
| GET | `/api/analysis/{job_id}/plugins` | Analysis log: every plugin run (rationale, args, timing, status, error, output hash). |
| GET | `/api/analysis/catalog/plugins` | Plugins used by the pipeline and why. |
| POST | `/api/demo/load` | Create a demo case from the synthetic dataset and analyse it (202). |

## Evidence

| Method | Path | Description |
|---|---|---|
| GET | `/api/processes?analysis_id=&suspicious_only=&search=` | Process list (risk-sorted). |
| GET | `/api/processes/tree?analysis_id=` | Nested process tree with risk, hidden/terminated/anomalous flags. |
| GET | `/api/processes/{pid}?analysis_id=&process_id=` | Detail: parent, children, modules, network, regions, handles, findings, SIDs, privileges. |
| GET | `/api/network?analysis_id=&suspicious_only=` | Network endpoints. |
| GET | `/api/memory-regions?analysis_id=&source=malfind|vadinfo&pid=` | Memory regions with hexdump/disasm. |
| GET | `/api/modules?analysis_id=&pid=&suspicious_only=` | Modules. |
| GET | `/api/timeline?analysis_id=&min_severity=` | Timeline (timestamped first, undated last). |
| GET | `/api/yara/matches?analysis_id=` | YARA matches. |

## Findings, rules and IOCs

| Method | Path | Description |
|---|---|---|
| GET | `/api/findings?analysis_id=&severity=&rule_id=&pid=&category=&min_confidence=&status=` | Findings (`severity` repeatable). |
| PATCH | `/api/findings/{id}` | `{"status": "open|needs_review|confirmed|false_positive"}`. |
| GET | `/api/findings/{id}/explanation?regenerate=` | Explainable-AI view (7 sections + validation). |
| GET | `/api/rules` | Rule catalogue. |
| PATCH | `/api/rules/{rule_id}` | `{"enabled": bool}` (admin). |
| GET | `/api/iocs?analysis_id=&type=&confidence=` | IOC table. |
| GET | `/api/iocs/export?analysis_id=&format=csv|json` | IOC export (demo exports are labelled). |

## AI assistant

| Method | Path | Description |
|---|---|---|
| POST | `/api/ai/query` | `{"analysis_id", "question"}` → `{answer, citations[], validation{status, unsupported_entities, ...}, provider, intents, retrieved}`. |
| GET | `/api/ai/history?analysis_id=` | Conversation history. |
| GET | `/api/ai/summary?analysis_id=&regenerate=` | Grounded investigation summary. |

Example:

```bash
curl -s -X POST http://localhost:8000/api/ai/query -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"analysis_id": 1, "question": "Why is PID 4528 suspicious?"}'
```

```json
{
  "answer": "### svchost.exe (PID 4528)\n**Risk score:** 100/100 (critical) [PROC-4528] ...",
  "citations": [{"id": "PROC-4528", "kind": "process", "title": "svchost.exe (PID 4528)", "pid": 4528}, ...],
  "validation": {"status": "grounded", "unsupported_entities": [], "unknown_citations": [], "overclaims": []},
  "provider": "deterministic", "intents": ["why_pid"], "retrieved": 23
}
```

## Reports

| Method | Path | Description |
|---|---|---|
| POST | `/api/reports/generate` | `{"analysis_id", "format": "pdf|html|json|csv"}` → report metadata incl. SHA-256 (custody event). |
| GET | `/api/reports?analysis_id=` | Generated reports. |
| GET | `/api/reports/{id}/download` | File download; header `X-Report-SHA256`. |

## Settings and system

| Method | Path | Description |
|---|---|---|
| GET | `/api/system/status` | Volatility availability/version, yara-python, AI provider, limits. |
| GET | `/api/scoring/model` | Scoring formula, caps, bands, disclaimer. |
| GET/PUT | `/api/settings/ai` | Provider, base URL, model, temperature (PUT admin). API key only via env. |
| POST | `/api/settings/ai/test` | Provider connectivity test (admin). |
| GET/POST | `/api/yara/rules` | List / upload `.yar` (validated; `include` rejected). |
| PATCH/DELETE | `/api/yara/rules/{id}` | Enable/disable / delete uploaded file (admin). |
| GET | `/api/dashboard` | Cross-case dashboard statistics. |
| GET | `/api/health` | Liveness. |
