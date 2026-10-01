"""REST API integration tests, including the full demo pipeline and report generation."""

from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile

from tests.conftest import wait_for_job


def test_health_and_auth_required(client):
    assert client.get("/api/health").json() == {"status": "ok"}
    assert client.get("/api/cases").status_code == 401
    assert client.get("/api/cases", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_login_failure_and_lockout(client):
    for _ in range(5):
        assert client.post("/api/auth/login", json={"username": "lockme", "password": "x"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "lockme", "password": "x"}).status_code == 429


def test_security_headers(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"


def test_case_upload_and_custody(client, auth):
    case = client.post("/api/cases", json={"title": "Upload test case"}, headers=auth).json()
    assert case["case_number"].startswith("CASE-")
    blob = os.urandom(8192)
    r = client.post("/api/memory/upload", data={"case_id": case["id"]},
                    files={"file": ("host01.raw", io.BytesIO(blob), "application/octet-stream")}, headers=auth)
    assert r.status_code == 201, r.text
    img = r.json()
    assert img["sha256"] == hashlib.sha256(blob).hexdigest() and img["format_hint"] == "raw"

    bad = client.post("/api/memory/upload", data={"case_id": case["id"]},
                      files={"file": ("x.zip", io.BytesIO(blob), "application/zip")}, headers=auth)
    assert bad.status_code == 422 and "Unsupported file type" in bad.json()["detail"]
    pdf = client.post("/api/memory/upload", data={"case_id": case["id"]},
                      files={"file": ("x.raw", io.BytesIO(b"%PDF" + blob), "application/octet-stream")}, headers=auth)
    assert pdf.status_code == 422

    verify = client.post(f"/api/memory/{img['id']}/verify", headers=auth).json()
    assert verify["match"] is True
    actions = [e["action"] for e in client.get(f"/api/cases/{case['id']}/custody", headers=auth).json()]
    assert actions[:2] == ["case_opened", "evidence_received"] and "integrity_verified" in actions


def test_invalid_image_fails_gracefully_with_real_volatility(client, auth):
    """Random bytes are not a Windows image: plugins fail, failures are logged, the job ends 'failed'."""
    status = client.get("/api/system/status", headers=auth).json()
    if not status["volatility"]["available"]:
        import pytest

        pytest.skip("Volatility 3 not installed")
    case = client.post("/api/cases", json={"title": "Corrupt image case"}, headers=auth).json()
    img = client.post("/api/memory/upload", data={"case_id": case["id"]},
                      files={"file": ("corrupt.mem", io.BytesIO(os.urandom(8192)), "application/octet-stream")},
                      headers=auth).json()
    job = client.post(f"/api/analysis/{img['id']}/start", json={"yara": False}, headers=auth).json()
    done = wait_for_job(client, auth, job["id"])
    assert done["status"] == "failed" and "No process listing" in done["error"]
    runs = client.get(f"/api/analysis/{job['id']}/plugins", headers=auth).json()
    assert runs[0]["plugin"] == "windows.info" and runs[0]["status"] == "failed" and runs[0]["error"]
    assert done["hash_verified_before"] is True


def test_demo_analysis_summary(client, auth, demo_job):
    detail = client.get(f"/api/analysis/{demo_job['id']}", headers=auth).json()
    s = detail["summary"]
    assert detail["image"]["is_demo"] and s["synthetic"] is True
    assert s["total_processes"] == 35 and s["hidden_candidates"] == 1
    assert s["overall_risk_band"] == "critical" and s["suspicious_processes"] >= 3
    assert detail["hash_verified_before"] and detail["hash_verified_after"]
    assert detail["image"]["os_info"]["os_name"] == "Windows 10"
    runs = client.get(f"/api/analysis/{demo_job['id']}/plugins", headers=auth).json()
    targeted = next(r for r in runs if r["plugin"] == "windows.handles")
    assert targeted["args"][0] == "--pid" and "4528" in targeted["args"]
    assert all(r["rationale"] for r in runs)


def test_processes_tree_and_detail(client, auth, demo_job):
    q = {"analysis_id": demo_job["id"]}
    procs = client.get("/api/processes", params={**q, "suspicious_only": True}, headers=auth).json()
    assert procs[0]["pid"] == 4528 and procs[0]["risk_score"] >= 80
    assert procs[0]["risk_contributors"]
    tree = client.get("/api/processes/tree", params=q, headers=auth).json()
    assert {n["name"] for n in tree} >= {"System"}
    detail = client.get("/api/processes/4528", params=q, headers=auth).json()
    assert detail["parent"]["pid"] == 4388 and any(c["pid"] == 5120 for c in detail["children"])
    assert detail["regions"] and detail["network"] and detail["findings"] and detail["modules"]
    assert any(p["privilege"] == "SeDebugPrivilege" for p in detail["privileges"])
    assert client.get("/api/processes/424242", params=q, headers=auth).status_code == 404


def test_findings_filters_and_status(client, auth, demo_job):
    q = {"analysis_id": demo_job["id"]}
    high = client.get("/api/findings", params={**q, "severity": ["high", "critical"]}, headers=auth).json()
    assert high and all(f["severity"] in ("high", "critical") for f in high)
    by_rule = client.get("/api/findings", params={**q, "rule_id": "RULE_PROCESS_HIDING"}, headers=auth).json()
    assert [f["pid"] for f in by_rule] == [6044]
    fid = by_rule[0]["id"]
    assert client.patch(f"/api/findings/{fid}", json={"status": "needs_review"}, headers=auth).json()["status"] == "needs_review"
    assert client.patch(f"/api/findings/{fid}", json={"status": "bogus"}, headers=auth).status_code == 422
    exp = client.get(f"/api/findings/{fid}/explanation", headers=auth).json()
    assert exp["content"]["does_not_prove"] and exp["grounded"]


def test_network_memory_iocs_timeline_yara(client, auth, demo_job):
    q = {"analysis_id": demo_job["id"]}
    net = client.get("/api/network", params={**q, "suspicious_only": True}, headers=auth).json()
    assert any(n["foreign_addr"] == "203.0.113.45" and n["foreign_port"] == 4444 for n in net)
    mem = client.get("/api/memory-regions", params={**q, "source": "malfind"}, headers=auth).json()
    assert any(r["has_pe_header"] and r["pid"] == 4528 for r in mem)
    iocs = client.get("/api/iocs", params=q, headers=auth).json()
    assert any(i["value"] == "update-check.example" for i in iocs)
    csv_text = client.get("/api/iocs/export", params={**q, "format": "csv"}, headers=auth).text
    assert csv_text.startswith("# DEMO DATA") and "203.0.113.45" in csv_text
    exported = client.get("/api/iocs/export", params={**q, "format": "json"}, headers=auth).json()
    assert exported["demo_data"] is True and exported["iocs"]
    tl = client.get("/api/timeline", params=q, headers=auth).json()
    from datetime import datetime

    stamped = [datetime.fromisoformat(t["timestamp"].replace("Z", "+00:00")) for t in tl if t["timestamp"]]
    assert stamped == sorted(stamped)
    assert any(t["timestamp"] is None or "anchored" in t["timestamp_source"] for t in tl)
    assert client.get("/api/yara/matches", params=q, headers=auth).json()


def test_ai_query_endpoint(client, auth, demo_job):
    r = client.post("/api/ai/query", json={"analysis_id": demo_job["id"], "question": "Why is PID 4528 suspicious?"},
                    headers=auth).json()
    assert r["citations"] and r["validation"]["unsupported_entities"] == []
    history = client.get("/api/ai/history", params={"analysis_id": demo_job["id"]}, headers=auth).json()
    assert [m["role"] for m in history[-2:]] == ["user", "assistant"]
    summary = client.get("/api/ai/summary", params={"analysis_id": demo_job["id"]}, headers=auth).json()
    assert "Investigation summary" in summary["markdown"]


def test_report_generation_all_formats(client, auth, demo_job):
    for fmt in ("html", "pdf", "json", "csv"):
        rep = client.post("/api/reports/generate", json={"analysis_id": demo_job["id"], "format": fmt}, headers=auth)
        assert rep.status_code == 201, rep.text
        meta = rep.json()
        dl = client.get(f"/api/reports/{meta['id']}/download", headers=auth)
        assert dl.status_code == 200 and hashlib.sha256(dl.content).hexdigest() == meta["sha256"]
        if fmt == "pdf":
            assert dl.content.startswith(b"%PDF")
        elif fmt == "html":
            html = dl.text
            assert "DEMO DATA" in html and "SHA-256" in html and "Chain of custody" in html
            assert "<script" not in html  # report content is escaped
        elif fmt == "json":
            data = json.loads(dl.content)
            assert data["is_demo"] and data["image"]["sha256"] and data["findings"]
        else:
            names = zipfile.ZipFile(io.BytesIO(dl.content)).namelist()
            assert {"findings.csv", "iocs.csv", "chain_of_custody.csv", "DEMO_DATA_NOTICE.txt"} <= set(names)
    case_id = client.get(f"/api/analysis/{demo_job['id']}", headers=auth).json()["case_id"]
    custody = client.get(f"/api/cases/{case_id}/custody", headers=auth).json()
    assert sum(1 for e in custody if e["action"] == "report_generated" and e["sha256"]) >= 4


def test_rules_yara_and_settings(client, auth):
    rules = client.get("/api/rules", headers=auth).json()
    assert len(rules) >= 15 and all(r["description"] for r in rules)
    r = client.patch("/api/rules/RULE_RWX_MEMORY", json={"enabled": False}, headers=auth).json()
    assert r["enabled"] is False
    client.patch("/api/rules/RULE_RWX_MEMORY", json={"enabled": True}, headers=auth)

    builtin = client.get("/api/yara/rules", headers=auth).json()
    assert any(y["builtin"] and "Reflective_Loader_Export_String" in y["rule_names"] for y in builtin)
    ok = client.post("/api/yara/rules", files={"file": ("t.yar", b'rule T { strings: $a = "x" condition: $a }')},
                     headers=auth)
    assert ok.status_code == 201
    inc = client.post("/api/yara/rules", files={"file": ("i.yar", b'include "/etc/passwd"\nrule T { condition: true }')},
                      headers=auth)
    assert inc.status_code == 422 and "include" in inc.json()["detail"]

    s = client.get("/api/settings/ai", headers=auth).json()
    assert s["provider"] == "deterministic" and "api_key" not in s
    assert client.post("/api/settings/ai/test", headers=auth).json()["ok"] is True
    model = client.get("/api/scoring/model", headers=auth).json()
    assert model["bands"][-1]["name"] == "critical" and "not an authoritative" in model["disclaimer"]


def test_dashboard(client, auth, demo_job):
    d = client.get("/api/dashboard", headers=auth).json()
    assert d["cases"] >= 1 and d["totals"]["total_processes"] >= 35
    assert any(a["id"] == demo_job["id"] for a in d["recent_analyses"])


def test_stored_strings_fit_declared_column_lengths(demo_job):
    """SQLite ignores VARCHAR lengths but PostgreSQL enforces them - guard against truncation errors."""
    from sqlalchemy import String, select

    from app.core.database import Base, SessionLocal

    db = SessionLocal()
    try:
        violations = []
        for table in Base.metadata.sorted_tables:
            limited = [c for c in table.columns if isinstance(c.type, String) and c.type.length]
            if not limited:
                continue
            for row in db.execute(select(*limited)).all():
                for col, value in zip(limited, row, strict=True):
                    if isinstance(value, str) and len(value) > col.type.length:
                        violations.append(f"{table.name}.{col.name}: {len(value)} > {col.type.length}")
        assert not violations, violations
    finally:
        db.close()
