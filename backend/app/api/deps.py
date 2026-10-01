from __future__ import annotations

import jwt
from fastapi import Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_access_token
from app.models import AnalysisJob, User

_bearer = HTTPBearer(auto_error=False)


def get_current_user(creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
                     db: Session = Depends(get_db)) -> User:
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated",
                                 headers={"WWW-Authenticate": "Bearer"})
    if creds is None:
        raise unauthorized
    try:
        payload = decode_access_token(creds.credentials)
    except jwt.PyJWTError as exc:
        raise unauthorized from exc
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator role required")
    return user


def get_job(analysis_id: int = Query(..., ge=1), db: Session = Depends(get_db),
            _: User = Depends(get_current_user)) -> AnalysisJob:
    job = db.get(AnalysisJob, analysis_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    return job


def job_by_path(job_id: int, db: Session) -> AnalysisJob:
    job = db.get(AnalysisJob, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    return job
