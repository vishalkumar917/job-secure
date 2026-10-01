"""Settings, YARA rule management, demo mode, dashboard and system status."""

from __future__ import annotations

import uuid
from collections import Counter
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.core.config import get_settings
from app.core.database import get_db
from app.models import AnalysisJob, AppSetting, Case, CustodyEvent, MemoryImage, User, YaraRuleFile
from app.schemas.common import AISettingsIn, AISettingsOut, JobOut, ToggleIn, YaraRuleOut
from app.services.ai.assistant import resolve_provider_config
from app.services.ai.providers import build_provider
from app.services.analysis.jobs import get_job_runner
from app.services.detection.knowledge import cached_knowledge_base
from app.services.evidence.custody import record_custody
from app.services.evidence.storage import compute_evidence_hash
from app.services.scoring.risk import ScoringModel
from app.services.volatility.runner import VolatilityRunner
from app.services.yara.manager import validate_rule_bytes, yara_python_available

router = APIRouter(prefix="/api", tags=["system"])


# ---------------------------------------------------------------- status & settings
@router.get("/system/status")
def system_status(db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> dict:
    settings = get_settings()
    cfg = resolve_provider_config(db)
    return {
        "volatility": VolatilityRunner.detect(settings),
        "yara_python": yara_python_available(),
        "ai": {"provider": cfg.provider, "model": cfg.model or None, "base_url": cfg.base_url or None},
        "limits": {"max_upload_bytes": settings.max_upload_bytes, "allowed_extensions": settings.allowed_extensions,
                   "plugin_timeout_seconds": settings.plugin_timeout_seconds,
                   "deep_scan_max_pids": settings.deep_scan_max_pids},
        "demo_available": (settings.sample_data_dir / "demo_case" / "manifest.json").exists(),
    }


@router.get("/scoring/model")
def scoring_model(_: User = Depends(get_current_user)) -> dict:
    kb = cached_knowledge_base(str(get_settings().rules_dir))
    return ScoringModel.from_config(kb.scoring).describe()


@router.get("/settings/ai", response_model=AISettingsOut)
def get_ai_settings(db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> AISettingsOut:
    cfg = resolve_provider_config(db)
    return AISettingsOut(provider=cfg.provider, base_url=cfg.base_url, model=cfg.model,
                         temperature=cfg.temperature, api_key_configured=bool(cfg.api_key))


@router.put("/settings/ai", response_model=AISettingsOut)
def put_ai_settings(body: AISettingsIn, db: Session = Depends(get_db),
                    _: User = Depends(require_admin)) -> AISettingsOut:
    """Runtime AI provider selection. API keys are only ever read from the AI_API_KEY environment variable."""
    row = db.get(AppSetting, "ai") or AppSetting(key="ai")
    row.value = body.model_dump()
    db.add(row)
    db.commit()
    return get_ai_settings(db)


@router.post("/settings/ai/test")
def test_ai(db: Session = Depends(get_db), _: User = Depends(require_admin)) -> dict:
    cfg = resolve_provider_config(db)
    provider = build_provider(cfg)
    if provider is None:
        return {"ok": True, "detail": "Deterministic engine (no external LLM) - always available."}
    return provider.health()


# ---------------------------------------------------------------- YARA
@router.get("/yara/rules", response_model=list[YaraRuleOut])
def list_yara(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return list(db.scalars(select(YaraRuleFile).order_by(YaraRuleFile.builtin.desc(), YaraRuleFile.id)).all())


@router.post("/yara/rules", response_model=YaraRuleOut, status_code=status.HTTP_201_CREATED)
def upload_yara(file: UploadFile = File(...), db: Session = Depends(get_db),
                user: User = Depends(get_current_user)) -> YaraRuleFile:
    name = Path(file.filename or "rules.yar").name
    if Path(name).suffix.lower() not in (".yar", ".yara"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "YARA rule files must have a .yar or .yara extension")
    data = file.file.read(1024 * 1024 + 1)
    info = validate_rule_bytes(data)
    settings = get_settings()
    settings.ensure_directories()
    dest = settings.user_yara_dir / f"{uuid.uuid4().hex}.yar"
    dest.write_bytes(data)
    row = YaraRuleFile(filename=name, stored_path=str(dest), sha256=info.sha256, rule_names=info.rule_names,
                       builtin=False, uploaded_by=user.id)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.patch("/yara/rules/{rule_file_id}", response_model=YaraRuleOut)
def toggle_yara(rule_file_id: int, body: ToggleIn, db: Session = Depends(get_db),
                _: User = Depends(get_current_user)) -> YaraRuleFile:
    row = db.get(YaraRuleFile, rule_file_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "YARA rule file not found")
    row.enabled = body.enabled
    db.commit()
    db.refresh(row)
    return row


@router.delete("/yara/rules/{rule_file_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_yara(rule_file_id: int, db: Session = Depends(get_db), _: User = Depends(require_admin)) -> None:
    row = db.get(YaraRuleFile, rule_file_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "YARA rule file not found")
    if row.builtin:
        raise HTTPException(status.HTTP_409_CONFLICT, "Built-in rule files can be disabled but not deleted")
    Path(row.stored_path).unlink(missing_ok=True)
    db.delete(row)
    db.commit()


# ---------------------------------------------------------------- demo mode
@router.post("/demo/load", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED)
def load_demo(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> AnalysisJob:
    """Create a demo case from the synthetic dataset and analyse it with the real pipeline."""
    settings = get_settings()
    bundle = settings.sample_data_dir / "demo_case"
    if not (bundle / "manifest.json").exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Demo dataset not found in sample_data/demo_case")
    n = (db.scalar(select(func.count(Case.id)).where(Case.is_demo)) or 0) + 1
    number = f"DEMO-{n:03d}"
    while db.scalar(select(Case.id).where(Case.case_number == number)):
        n += 1
        number = f"DEMO-{n:03d}"
    case = Case(case_number=number, title="Demo investigation - synthetic workstation compromise",
                description="DEMO DATA - NOT REAL FORENSIC EVIDENCE. Synthetic Volatility-format output that "
                            "simulates a macro-initiated intrusion for demonstration and teaching.",
                investigator_id=user.id, is_demo=True)
    db.add(case)
    db.flush()
    digest = compute_evidence_hash(bundle)
    image = MemoryImage(case_id=case.id, original_filename="DEMO-synthetic-win10-x64.vmem (synthetic bundle)",
                        stored_path=str(bundle), size_bytes=sum(f.stat().st_size for f in bundle.glob("*.json")),
                        sha256=digest, format_hint="demo", is_demo=True, uploaded_by=user.id,
                        validation_notes=["Synthetic demo bundle - SHA-256 is computed over the bundle manifest, "
                                          "not over a memory image."])
    db.add(image)
    db.flush()
    record_custody(db, case_id=case.id, action="case_opened", actor=user.username, details=f"Demo case {number}")
    record_custody(db, case_id=case.id, image_id=image.id, action="evidence_received", actor=user.username,
                   sha256=digest, details="Synthetic demo dataset loaded (NOT real evidence).")
    job = AnalysisJob(image_id=image.id, requested_by=user.id, options={"yara": True, "demo": True})
    db.add(job)
    db.flush()
    record_custody(db, case_id=case.id, image_id=image.id, job_id=job.id, action="analysis_requested",
                   actor=user.username, details=f"Analysis #{job.id} queued")
    db.commit()
    db.refresh(job)
    get_job_runner().submit(job.id)
    return job


# ---------------------------------------------------------------- dashboard
@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> dict:
    jobs = db.scalars(select(AnalysisJob).order_by(AnalysisJob.id.desc()).limit(200)).all()
    latest_per_image: dict[int, AnalysisJob] = {}
    for j in jobs:
        if j.status.startswith("completed") and j.image_id not in latest_per_image:
            latest_per_image[j.image_id] = j
    sev: Counter = Counter()
    totals: Counter = Counter()
    for j in latest_per_image.values():
        s = j.summary or {}
        sev.update(s.get("severity_counts") or {})
        for k in ("total_processes", "suspicious_processes", "network_connections", "suspicious_connections",
                  "injected_memory_indicators", "iocs", "high_severity_findings", "findings"):
            totals[k] += s.get(k, 0) or 0
    recent = []
    for j in jobs[:10]:
        img = j.image
        recent.append({"id": j.id, "status": j.status, "progress": j.progress, "stage": j.stage,
                       "risk_score": j.overall_risk_score, "risk_band": j.overall_risk_band,
                       "image": img.original_filename, "is_demo": img.is_demo, "case_id": img.case_id,
                       "case_number": img.case.case_number, "created_at": j.created_at})
    custody = db.scalars(select(CustodyEvent).order_by(CustodyEvent.timestamp.desc()).limit(10)).all()
    return {
        "cases": db.scalar(select(func.count(Case.id))) or 0,
        "open_cases": db.scalar(select(func.count(Case.id)).where(Case.status == "open")) or 0,
        "images": db.scalar(select(func.count(MemoryImage.id))) or 0,
        "analyses": db.scalar(select(func.count(AnalysisJob.id))) or 0,
        "running": sum(1 for j in jobs if j.status in ("queued", "running")),
        "totals": dict(totals),
        "severity_counts": {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
        "risk_bands": dict(Counter(j.overall_risk_band for j in latest_per_image.values() if j.overall_risk_band)),
        "recent_analyses": recent,
        "recent_custody": [{"action": c.action, "actor": c.actor, "timestamp": c.timestamp, "details": c.details,
                            "case_id": c.case_id} for c in custody],
    }
