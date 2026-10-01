"""FastAPI application entry point."""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.api.routes import ai, analysis, auth, cases, evidence, findings, memory, reports, system
from app.core import config as config_module
from app.core.config import get_settings
from app.core.database import SessionLocal, create_all, init_engine
from app.core.exceptions import ForensicsError
from app.core.logging import configure_logging, get_logger
from app.core.security import hash_password
from app.models import RuleDefinition, User, YaraRuleFile
from app.services.analysis.jobs import get_job_runner
from app.services.detection.base import RULE_REGISTRY
from app.services.detection.engine import rule_catalog  # noqa: F401 - ensures rules are registered
from app.services.yara.manager import parse_rule_text

log = get_logger("app")


def seed(db) -> None:
    settings = get_settings()
    if db.scalar(select(User).where(User.username == settings.admin_username)) is None:
        db.add(User(username=settings.admin_username, full_name="Administrator", role="admin",
                    password_hash=hash_password(settings.admin_password.get_secret_value())))
        if settings.admin_password.get_secret_value() == "ChangeMe!2026":
            log.warning("default admin password in use - set ADMIN_PASSWORD before any real deployment")

    existing = {r.rule_id: r for r in db.scalars(select(RuleDefinition)).all()}
    for rule_id, cls in RULE_REGISTRY.items():
        meta = cls.metadata()
        row = existing.get(rule_id) or RuleDefinition(rule_id=rule_id, enabled=True)
        row.title, row.category, row.default_severity = meta["title"], meta["category"], meta["default_severity"]
        row.base_points, row.description, row.attack_techniques = meta["base_points"], meta["description"], \
            meta["attack_techniques"]
        db.add(row)

    known = {y.stored_path for y in db.scalars(select(YaraRuleFile).where(YaraRuleFile.builtin)).all()}
    if settings.yara_rules_dir.exists():
        for f in sorted(settings.yara_rules_dir.glob("*.yar*")):
            if str(f) in known:
                continue
            names, _ = parse_rule_text(f.read_text(encoding="utf-8", errors="replace"))
            db.add(YaraRuleFile(filename=f.name, stored_path=str(f), sha256=hashlib.sha256(f.read_bytes()).hexdigest(),
                                rule_names=names, builtin=True, enabled=True))
    db.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    settings.ensure_directories()
    init_engine()
    create_all()
    db = SessionLocal()
    try:
        seed(db)
    finally:
        db.close()
    if config_module.secret_was_generated:
        log.warning("SECRET_KEY not set - generated an ephemeral key; sessions end when the server restarts")
    runner = get_job_runner()
    runner.recover()
    log.info("application started", extra={"environment": settings.environment})
    yield
    runner.shutdown()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="MemTrace API",
        description="AI-Assisted Windows Malware Memory Forensics & Analysis System. "
                    "Defensive digital-forensics platform: analyses memory images with Volatility 3, "
                    "rule-based detection, explainable risk scoring and grounded AI explanations.",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                       allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
                       allow_headers=["Authorization", "Content-Type"],
                       expose_headers=["Content-Disposition", "X-Report-SHA256"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.exception_handler(ForensicsError)
    async def forensic_error(_: Request, exc: ForensicsError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.message, **exc.detail})

    for r in (auth, cases, memory, analysis, evidence, findings, ai, reports, system):
        app.include_router(r.router)

    @app.get("/api/health", tags=["system"])
    def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
