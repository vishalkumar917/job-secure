"""Chain-of-custody event recording.

Each significant action on evidence (intake, integrity verification, analysis
start/finish, report generation) is appended as an immutable event with the
actor, UTC timestamp and, where relevant, a SHA-256 value.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import CustodyEvent


def record_custody(db: Session, *, case_id: int, action: str, actor: str, details: str = "",
                   image_id: int | None = None, job_id: int | None = None,
                   sha256: str | None = None) -> CustodyEvent:
    event = CustodyEvent(case_id=case_id, image_id=image_id, job_id=job_id, action=action,
                         actor=actor, details=details, sha256=sha256)
    db.add(event)
    db.flush()
    return event
