# Database Design

SQLAlchemy 2.0 models in `backend/app/models/`. SQLite (WAL mode) is used for development and PostgreSQL
for production (`DATABASE_URL=postgresql+psycopg://...`). The complete DDL generated from the models is in
[`schema.sql`](schema.sql) (`python scripts/export_schema.py postgresql > docs/schema.sql`).

## ER diagram

```mermaid
erDiagram
    users ||--o{ cases : investigates
    cases ||--o{ memory_images : contains
    cases ||--o{ custody_events : "chain of custody"
    memory_images ||--o{ analysis_jobs : analysed_by
    analysis_jobs ||--o{ plugin_runs : logs
    analysis_jobs ||--o{ processes : extracts
    analysis_jobs ||--o{ process_relationships : ""
    processes ||--o{ process_relationships : "parent/child"
    analysis_jobs ||--o{ modules : ""
    analysis_jobs ||--o{ network_connections : ""
    analysis_jobs ||--o{ memory_regions : ""
    analysis_jobs ||--o{ handles : ""
    analysis_jobs ||--o{ yara_matches : ""
    analysis_jobs ||--o{ findings : ""
    analysis_jobs ||--o{ iocs : ""
    analysis_jobs ||--o{ timeline_events : ""
    analysis_jobs ||--o{ ai_analysis : ""
    analysis_jobs ||--o{ chat_messages : ""
    analysis_jobs ||--o{ reports : ""
    processes ||--o{ modules : loads
    processes ||--o{ network_connections : owns
    processes ||--o{ memory_regions : maps
    processes ||--o{ handles : holds
    processes ||--o{ findings : "subject of"
    processes ||--o{ iocs : "source of"
    findings ||--o{ ai_analysis : explained_by
    rules ||..o{ findings : "rule_id"

    users {
        int id PK
        string username UK
        string password_hash
        string role
    }
    cases {
        int id PK
        string case_number UK
        string title
        string status
        bool is_demo
        int investigator_id FK
    }
    memory_images {
        int id PK
        int case_id FK
        string original_filename
        string stored_path
        bigint size_bytes
        string sha256
        string format_hint
        json os_info
        bool is_demo
    }
    analysis_jobs {
        int id PK
        int image_id FK
        string status
        string stage
        int progress
        bool hash_verified_before
        bool hash_verified_after
        int overall_risk_score
        json summary
    }
    plugin_runs {
        int id PK
        int job_id FK
        string plugin
        json args
        string status
        int duration_ms
        int row_count
        string error
        string output_sha256
    }
    custody_events {
        int id PK
        int case_id FK
        int image_id FK
        int job_id FK
        string action
        string actor
        datetime timestamp
        string sha256
    }
    processes {
        int id PK
        int job_id FK
        int pid
        int ppid
        string name
        text path
        text cmdline
        datetime create_time
        bool is_hidden_candidate
        int risk_score
        json risk_contributors
    }
    process_relationships {
        int id PK
        int parent_process_id FK
        int child_process_id FK
        bool is_anomalous
    }
    modules {
        int id PK
        int process_id FK
        string name
        text path
        string base
        bool is_suspicious
    }
    network_connections {
        int id PK
        int process_id FK
        string protocol
        string foreign_addr
        int foreign_port
        string state
        bool is_suspicious
    }
    memory_regions {
        int id PK
        int process_id FK
        string source
        string start
        string end
        string protection
        bool has_pe_header
        text hexdump
    }
    handles {
        int id PK
        int process_id FK
        string handle_type
        string granted_access
        text name
    }
    yara_matches {
        int id PK
        int process_id FK
        string rule_name
        string offset
    }
    findings {
        int id PK
        int process_id FK
        string rule_id
        string severity
        float confidence
        text finding
        json evidence
        string status
    }
    iocs {
        int id PK
        int process_id FK
        string ioc_type
        text value
        string source
        string confidence
        bool watchlist_match
    }
    rules {
        string rule_id PK
        string category
        int base_points
        bool enabled
    }
    timeline_events {
        int id PK
        datetime timestamp
        string event_type
        string evidence_ref
        string severity
    }
    ai_analysis {
        int id PK
        int finding_id FK
        string kind
        string provider
        json content
        json validation
        bool grounded
    }
    chat_messages {
        int id PK
        int user_id FK
        string role
        text content
        json citations
        json validation
    }
    reports {
        int id PK
        string report_format
        string path
        string sha256
        int size_bytes
    }
    yara_rule_files {
        int id PK
        string filename
        string sha256
        json rule_names
        bool builtin
        bool enabled
    }
    app_settings {
        string key PK
        json value
    }
```

## Tables

| Table | Purpose |
|---|---|
| `users` | Investigators/administrators (PBKDF2-SHA256 hashes). |
| `cases` | Investigation container; `case_number` unique; demo cases flagged. |
| `memory_images` | Evidence metadata: original name, generated stored path, size, **SHA-256**, format, intake notes, OS identification. |
| `analysis_jobs` | One analysis run: status/stage/progress, integrity verification before/after, overall risk, JSON summary, Volatility version. Re-analysis creates a new job; artifacts never mix. |
| `plugin_runs` | Analysis log - every plugin execution with rationale, args, timing, status, error, raw-output SHA-256. |
| `custody_events` | Append-only chain of custody. |
| `processes` | Merged process model with source flags (pslist/psscan/pstree), hidden/terminated flags, SIDs, privileges, risk score and signed contributors. |
| `process_relationships` | Parent/child edges (PID-reuse aware) with anomaly flag - drives the process tree. |
| `modules` | dlllist entries enriched with ldrmodules flags and suspicion reasons. |
| `network_connections` | netscan endpoints, external flag and heuristic reasons. |
| `memory_regions` | malfind regions (all) and executable vadinfo regions for triaged processes; hexdump/disasm. |
| `handles` | Handles of triaged processes. |
| `yara_matches` | vadyarascan results with severity from rule metadata. |
| `findings` | Rule results with evidence JSON, confidence, points, ATT&CK IDs, investigator status. |
| `iocs` | Extracted indicators with provenance and confidence. |
| `rules` | Rule catalogue synced from code; enable/disable flag. |
| `timeline_events` | Timestamped (or explicitly undated) events with time source. |
| `ai_analysis` | Cached explanations and case summaries with provider and validation report. |
| `chat_messages` | Assistant conversation history with citations and validation. |
| `reports` | Generated reports with SHA-256 (also recorded in custody). |
| `yara_rule_files` | Built-in and uploaded YARA files. |
| `app_settings` | Runtime settings (AI provider; never API keys). |

## Indexes

| Index | Supports |
|---|---|
| `ix_process_job_pid (job_id, pid)` | process detail look-ups |
| `ix_process_job_risk (job_id, risk_score)` | ranked / suspicious-only lists |
| `ix_module_job_pid`, `ix_net_job_pid`, `ix_region_job_pid` | per-process detail tabs |
| `ix_finding_job_sev (job_id, severity)`, `ix_findings_rule_id`, `ix_findings_category` | findings filters |
| `ix_ioc_job_type (job_id, ioc_type)` | IOC explorer filters |
| `ix_timeline_events_timestamp` | timeline ordering |
| `ix_custody_case_time (case_id, timestamp)` | chain-of-custody view |
| `ix_memory_images_sha256` | locating evidence by hash |
| every `job_id` / `process_id` FK | joins and cascade deletes |

## Integrity and deletion semantics

* Deleting a case cascades to its images, jobs and all derived artifacts (`ON DELETE CASCADE`).
* User deletion sets references to NULL so custody records remain.
* Memory addresses are hex strings (64-bit kernel addresses overflow signed BIGINT).
* All timestamps are stored in UTC (`TIMESTAMP WITH TIME ZONE` on PostgreSQL).
* Schema migrations: tables are created with `create_all`; Alembic is listed as future work.
