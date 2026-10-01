from __future__ import annotations

import csv
import io
import json

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_job, job_by_path, require_admin
from app.core.database import get_db
from app.models import IOC, AnalysisJob, Finding, RuleDefinition, User
from app.schemas.common import ExplanationOut, FindingOut, FindingUpdate, IOCOut, RuleOut, ToggleIn
from app.services.ai.assistant import ForensicAssistant

router = APIRouter(prefix="/api", tags=["findings, rules & IOCs"])
SEV = ["info", "low", "medium", "high", "critical"]


@router.get("/findings", response_model=list[FindingOut])
def list_findings(job: AnalysisJob = Depends(get_job), db: Session = Depends(get_db),
                  severity: list[str] | None = Query(None), rule_id: str | None = None, pid: int | None = None,
                  category: str | None = None, min_confidence: float = Query(0, ge=0, le=1),
                  status_filter: str | None = Query(None, alias="status")):
    q = select(Finding).where(Finding.job_id == job.id, Finding.confidence >= min_confidence)
    if severity:
        q = q.where(Finding.severity.in_(severity))
    if rule_id:
        q = q.where(Finding.rule_id == rule_id)
    if pid is not None:
        q = q.where(Finding.pid == pid)
    if category:
        q = q.where(Finding.category == category)
    if status_filter:
        q = q.where(Finding.status == status_filter)
    rows = db.scalars(q).all()
    return sorted(rows, key=lambda f: (-SEV.index(f.severity) if f.severity in SEV else 0, -f.confidence, f.id))


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: int, body: FindingUpdate, db: Session = Depends(get_db),
                   _: User = Depends(get_current_user)) -> Finding:
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    f.status = body.status
    db.commit()
    db.refresh(f)
    return f


@router.get("/findings/{finding_id}/explanation", response_model=ExplanationOut)
def explain(finding_id: int, regenerate: bool = False, db: Session = Depends(get_db),
            _: User = Depends(get_current_user)) -> ExplanationOut:
    """Explainable-AI view of a finding: what happened, why, evidence, confidence, limits, next steps."""
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    row = ForensicAssistant(db, job_by_path(f.job_id, db)).explain_finding(f, regenerate=regenerate)
    return ExplanationOut(finding_id=f.id, provider=row.provider, model=row.model, content=row.content,
                          validation=row.validation, grounded=row.grounded, created_at=row.created_at)


@router.get("/rules", response_model=list[RuleOut])
def list_rules(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return list(db.scalars(select(RuleDefinition).order_by(RuleDefinition.category, RuleDefinition.rule_id)).all())


@router.patch("/rules/{rule_id}", response_model=RuleOut)
def toggle_rule(rule_id: str, body: ToggleIn, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    rule = db.get(RuleDefinition, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    rule.enabled = body.enabled
    db.commit()
    db.refresh(rule)
    return rule


@router.get("/iocs", response_model=list[IOCOut])
def list_iocs(job: AnalysisJob = Depends(get_job), db: Session = Depends(get_db),
              ioc_type: str | None = Query(None, alias="type"), confidence: str | None = None):
    q = select(IOC).where(IOC.job_id == job.id)
    if ioc_type:
        q = q.where(IOC.ioc_type == ioc_type)
    if confidence:
        q = q.where(IOC.confidence == confidence)
    return list(db.scalars(q.order_by(IOC.id)).all())


@router.get("/iocs/export")
def export_iocs(job: AnalysisJob = Depends(get_job), db: Session = Depends(get_db),
                fmt: str = Query("csv", alias="format", pattern=r"^(csv|json)$")) -> Response:
    rows = [IOCOut.model_validate(i).model_dump() for i in
            db.scalars(select(IOC).where(IOC.job_id == job.id).order_by(IOC.id)).all()]
    demo = job.image.is_demo
    name = f"iocs_analysis_{job.id}{'_DEMO' if demo else ''}.{fmt}"
    if fmt == "json":
        body = json.dumps({"analysis_id": job.id, "evidence_sha256": job.image.sha256, "demo_data": demo,
                           "iocs": rows}, indent=2)
        media = "application/json"
    else:
        buf = io.StringIO()
        fields = ["ioc_type", "value", "source", "process_name", "pid", "confidence", "context", "watchlist_match"]
        w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
        body = ("# DEMO DATA - NOT REAL FORENSIC EVIDENCE\n" if demo else "") + buf.getvalue()
        media = "text/csv"
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'})
