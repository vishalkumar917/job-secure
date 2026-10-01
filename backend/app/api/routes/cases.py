from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models import AnalysisJob, Case, CustodyEvent, MemoryImage, User
from app.schemas.common import CaseCreate, CaseDetail, CaseOut, CaseUpdate, CustodyOut, ImageOut, JobOut
from app.services.evidence.custody import record_custody

router = APIRouter(prefix="/api/cases", tags=["cases"])


def _next_case_number(db: Session) -> str:
    year = datetime.now(timezone.utc).year
    n = (db.scalar(select(func.count(Case.id))) or 0) + 1
    while True:
        candidate = f"CASE-{year}-{n:04d}"
        if not db.scalar(select(Case.id).where(Case.case_number == candidate)):
            return candidate
        n += 1


@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
def create_case(body: CaseCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> Case:
    number = body.case_number or _next_case_number(db)
    if db.scalar(select(Case.id).where(Case.case_number == number)):
        raise HTTPException(status.HTTP_409_CONFLICT, f"Case number {number} already exists")
    case = Case(case_number=number, title=body.title.strip(), description=body.description.strip(),
                investigator_id=user.id)
    db.add(case)
    db.flush()
    record_custody(db, case_id=case.id, action="case_opened", actor=user.username, details=f"Case {number} opened")
    db.commit()
    db.refresh(case)
    return case


@router.get("", response_model=list[CaseOut])
def list_cases(db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> list[Case]:
    return list(db.scalars(select(Case).order_by(Case.created_at.desc())).all())


@router.get("/{case_id}", response_model=CaseDetail)
def get_case(case_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> CaseDetail:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Case not found")
    jobs = db.scalars(select(AnalysisJob).join(MemoryImage).where(MemoryImage.case_id == case_id)
                      .order_by(AnalysisJob.id.desc())).all()
    return CaseDetail.model_validate({**CaseOut.model_validate(case).model_dump(),
                                      "images": [ImageOut.model_validate(i) for i in case.images],
                                      "jobs": [JobOut.model_validate(j) for j in jobs]})


@router.patch("/{case_id}", response_model=CaseOut)
def update_case(case_id: int, body: CaseUpdate, db: Session = Depends(get_db),
                user: User = Depends(get_current_user)) -> Case:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Case not found")
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(case, k, v)
    if "status" in changes:
        record_custody(db, case_id=case.id, action=f"case_{changes['status']}", actor=user.username)
    db.commit()
    db.refresh(case)
    return case


@router.get("/{case_id}/custody", response_model=list[CustodyOut])
def custody(case_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> list[CustodyEvent]:
    if db.get(Case, case_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Case not found")
    return list(db.scalars(select(CustodyEvent).where(CustodyEvent.case_id == case_id)
                           .order_by(CustodyEvent.timestamp)).all())
