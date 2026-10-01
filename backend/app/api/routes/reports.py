from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_job, job_by_path
from app.core.config import get_settings
from app.core.database import get_db
from app.models import AnalysisJob, Report, User
from app.schemas.common import ReportOut, ReportRequest
from app.services.evidence.custody import record_custody
from app.services.reporting.builder import build_report_data
from app.services.reporting.renderers import EXTENSIONS, RENDERERS

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post("/generate", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
def generate(body: ReportRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> Report:
    job = job_by_path(body.analysis_id, db)
    if job.status not in ("completed", "completed_with_errors"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Reports can only be generated for completed analyses")
    settings = get_settings()
    settings.ensure_directories()
    data = build_report_data(db, job, user.username)
    render, _ = RENDERERS[body.format]
    content = render(data)
    digest = hashlib.sha256(content).hexdigest()
    case_no = job.image.case.case_number
    name = f"{case_no}_analysis{job.id}{'_DEMO' if job.image.is_demo else ''}_{digest[:8]}.{EXTENSIONS[body.format]}"
    path = settings.reports_dir / name
    path.write_bytes(content)
    report = Report(job_id=job.id, report_format=body.format, path=str(path), sha256=digest,
                    size_bytes=len(content), generated_by=user.id)
    db.add(report)
    record_custody(db, case_id=job.image.case_id, image_id=job.image_id, job_id=job.id, action="report_generated",
                   actor=user.username, sha256=digest, details=f"{body.format.upper()} report {name}")
    db.commit()
    db.refresh(report)
    return report


@router.get("", response_model=list[ReportOut])
def list_reports(job: AnalysisJob = Depends(get_job), db: Session = Depends(get_db)):
    return list(db.scalars(select(Report).where(Report.job_id == job.id).order_by(Report.id.desc())).all())


@router.get("/{report_id}/download")
def download(report_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> FileResponse:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    path = Path(report.path)
    settings = get_settings()
    if not path.resolve().is_relative_to(settings.reports_dir.resolve()) or not path.is_file():
        raise HTTPException(status.HTTP_410_GONE, "Report file is no longer available")
    _, media = RENDERERS[report.report_format]
    return FileResponse(path, media_type=media, filename=path.name,
                        headers={"X-Report-SHA256": report.sha256})
