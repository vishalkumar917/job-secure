from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.core.database import get_db
from app.models import Case, MemoryImage, User
from app.schemas.common import ImageOut
from app.services.evidence.custody import record_custody
from app.services.evidence.storage import compute_evidence_hash, store_stream

router = APIRouter(prefix="/api/memory", tags=["memory images"])


@router.post("/upload", response_model=ImageOut, status_code=status.HTTP_201_CREATED)
def upload(request: Request, case_id: int = Form(...), file: UploadFile = File(...),
           db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> MemoryImage:
    """Upload a memory image (.raw, .mem, .dmp, .vmem). Hashes with SHA-256 and stores it read-only."""
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Case not found")
    if case.status != "open":
        raise HTTPException(status.HTTP_409_CONFLICT, "Evidence cannot be added to a closed case")
    settings = get_settings()
    declared = request.headers.get("content-length")
    stored = store_stream(file.file, file.filename or "upload.raw", settings,
                          declared_size=int(declared) if declared and declared.isdigit() else None)
    image = MemoryImage(case_id=case.id, original_filename=stored.original_filename, stored_path=str(stored.path),
                        size_bytes=stored.size_bytes, sha256=stored.sha256, format_hint=stored.format_hint,
                        validation_notes=stored.notes, uploaded_by=user.id)
    db.add(image)
    db.flush()
    record_custody(db, case_id=case.id, image_id=image.id, action="evidence_received", actor=user.username,
                   sha256=stored.sha256,
                   details=f"Received '{stored.original_filename}' ({stored.size_bytes} bytes, {stored.format_hint}). "
                           "SHA-256 computed during intake; file stored read-only under a generated name.")
    db.commit()
    db.refresh(image)
    return image


@router.get("", response_model=list[ImageOut])
def list_images(case_id: int | None = None, db: Session = Depends(get_db),
                _: User = Depends(get_current_user)) -> list[MemoryImage]:
    q = select(MemoryImage).order_by(MemoryImage.uploaded_at.desc())
    if case_id is not None:
        q = q.where(MemoryImage.case_id == case_id)
    return list(db.scalars(q).all())


@router.get("/{image_id}", response_model=ImageOut)
def get_image(image_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> MemoryImage:
    image = db.get(MemoryImage, image_id)
    if image is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Memory image not found")
    return image


@router.post("/{image_id}/verify")
def verify_image(image_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    """Re-compute the SHA-256 of stored evidence and compare it with the intake hash."""
    image = db.get(MemoryImage, image_id)
    if image is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Memory image not found")
    path = Path(image.stored_path)
    if not path.exists():
        raise HTTPException(status.HTTP_410_GONE, "Evidence file is missing from the evidence store")
    current = compute_evidence_hash(path)
    match = current == image.sha256
    record_custody(db, case_id=image.case_id, image_id=image.id, action="integrity_verified", actor=user.username,
                   sha256=current, details="Manual verification: " + ("hash matches intake" if match else
                                                                      "HASH MISMATCH"))
    db.commit()
    return {"image_id": image.id, "intake_sha256": image.sha256, "current_sha256": current, "match": match}
