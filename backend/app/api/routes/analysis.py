from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, job_by_path
from app.core.config import get_settings
from app.core.database import get_db
from app.models import AnalysisJob, MemoryImage, PluginRun, User
from app.schemas.common import AnalysisStart, ImageOut, JobDetail, JobOut, PluginRunOut
from app.services.analysis.jobs import get_job_runner
from app.services.evidence.custody import record_custody
from app.services.volatility.plugins import PLUGINS
from app.services.volatility.runner import VolatilityRunner

router = APIRouter(prefix="/api/analysis", tags=["analysis"])


@router.get("/catalog/plugins")
def plugin_catalog(_: User = Depends(get_current_user)) -> list[dict]:
    """The Volatility plugins used by the pipeline and why each one is run."""
    return [{"name": p.name, "stage": p.stage, "rationale": p.rationale, "targeted": p.targeted,
             "optional": p.optional} for p in PLUGINS.values()]


@router.post("/{image_id}/start", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED)
def start(image_id: int, body: AnalysisStart | None = None, db: Session = Depends(get_db),
          user: User = Depends(get_current_user)) -> AnalysisJob:
    image = db.get(MemoryImage, image_id)
    if image is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Memory image not found")
    if not image.is_demo:
        vol = VolatilityRunner.detect(get_settings())
        if not vol["available"]:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, vol["message"])
    active = db.scalar(select(AnalysisJob).where(AnalysisJob.image_id == image_id,
                                                 AnalysisJob.status.in_(["queued", "running"])))
    if active:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Analysis #{active.id} is already {active.status}")
    job = AnalysisJob(image_id=image.id, requested_by=user.id, options=(body or AnalysisStart()).model_dump())
    db.add(job)
    db.flush()
    record_custody(db, case_id=image.case_id, image_id=image.id, job_id=job.id, action="analysis_requested",
                   actor=user.username, details=f"Analysis #{job.id} queued")
    db.commit()
    db.refresh(job)
    get_job_runner().submit(job.id)
    return job


@router.get("", response_model=list[JobOut])
def list_jobs(limit: int = 50, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return list(db.scalars(select(AnalysisJob).order_by(AnalysisJob.id.desc()).limit(min(limit, 200))).all())


@router.get("/{job_id}/status", response_model=JobOut)
def job_status(job_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> AnalysisJob:
    return job_by_path(job_id, db)


@router.get("/{job_id}", response_model=JobDetail)
def job_detail(job_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> JobDetail:
    job = job_by_path(job_id, db)
    case = job.image.case
    return JobDetail.model_validate({**JobOut.model_validate(job).model_dump(), "summary": job.summary or {},
                                     "image": ImageOut.model_validate(job.image), "case_id": case.id,
                                     "case_number": case.case_number, "case_title": case.title})


@router.get("/{job_id}/plugins", response_model=list[PluginRunOut])
def plugin_runs(job_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    job_by_path(job_id, db)
    return list(db.scalars(select(PluginRun).where(PluginRun.job_id == job_id).order_by(PluginRun.id)).all())
