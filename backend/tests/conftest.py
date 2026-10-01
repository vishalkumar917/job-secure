"""Shared fixtures. Environment is configured before the application is imported so the cached
settings point at an isolated temporary data directory and database."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
PROJECT = BACKEND.parent
FIXTURES = Path(__file__).parent / "fixtures"
_TMP = Path(tempfile.mkdtemp(prefix="memtrace-test-"))

os.environ.update({
    "DATA_DIR": str(_TMP / "data"),
    "DATABASE_URL": f"sqlite:///{(_TMP / 'test.db').as_posix()}",
    "RULES_DIR": str(PROJECT / "rules"),
    "YARA_RULES_DIR": str(PROJECT / "yara_rules"),
    "SAMPLE_DATA_DIR": str(PROJECT / "sample_data"),
    "SECRET_KEY": "test-secret-key-for-unit-tests-only-0123456789",
    "ADMIN_USERNAME": "admin",
    "ADMIN_PASSWORD": "Test-Password-1",
    "MIN_IMAGE_BYTES": "4096",
    "AI_PROVIDER": "deterministic",
    "ENVIRONMENT": "test",
    "PLUGIN_TIMEOUT_SECONDS": "120",
})
sys.path.insert(0, str(BACKEND))


def pytest_sessionfinish(session, exitstatus):  # noqa: ARG001
    shutil.rmtree(_TMP, ignore_errors=True)


@pytest.fixture(scope="session")
def settings():
    from app.core.config import get_settings

    s = get_settings()
    s.ensure_directories()
    return s


@pytest.fixture(scope="session")
def client(settings):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def auth(client) -> dict[str, str]:
    r = client.post("/api/auth/login", json={"username": "admin", "password": "Test-Password-1"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def wait_for_job(client, auth, job_id: int, timeout: float = 240) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/analysis/{job_id}/status", headers=auth).json()
        if job["status"] in ("completed", "completed_with_errors", "failed"):
            return job
        time.sleep(0.3)
    raise AssertionError(f"analysis {job_id} did not finish in {timeout}s")


@pytest.fixture(scope="session")
def demo_job(client, auth) -> dict:
    r = client.post("/api/demo/load", headers=auth)
    assert r.status_code == 202, r.text
    job = wait_for_job(client, auth, r.json()["id"])
    assert job["status"] == "completed", job
    return job


@pytest.fixture(scope="session")
def kb():
    from app.services.detection.knowledge import load_knowledge_base

    return load_knowledge_base(PROJECT / "rules")


@pytest.fixture(scope="session")
def demo_evidence():
    """Demo bundle parsed exactly as the pipeline would (all plugins, deep-dive for triaged PIDs)."""
    from app.services.analysis.pipeline import PARSERS
    from app.services.analysis.sources import DemoSource
    from app.services.volatility.parsers import ParsedEvidence

    src = DemoSource(PROJECT / "sample_data" / "demo_case")
    ev = ParsedEvidence()
    for plugin, (attr, parser) in PARSERS.items():
        res = src.run(plugin)
        if res.ok:
            ev.available.add(plugin)
            getattr(ev, attr).extend(parser(res.rows))
    return ev
