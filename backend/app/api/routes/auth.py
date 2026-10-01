from __future__ import annotations

import time
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.core.security import create_access_token, verify_password
from app.models import User
from app.schemas.common import LoginRequest, TokenOut, UserOut

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Simple brute-force protection: 5 failures per (ip, username) within 5 minutes locks that pair.
_FAILURES: dict[tuple[str, str], list[float]] = defaultdict(list)
_WINDOW, _MAX_FAILURES = 300, 5


def _check_lock(key: tuple[str, str]) -> None:
    now = time.monotonic()
    _FAILURES[key] = [t for t in _FAILURES[key] if now - t < _WINDOW]
    if len(_FAILURES[key]) >= _MAX_FAILURES:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts. Try again later.")


@router.post("/login", response_model=TokenOut)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenOut:
    key = (request.client.host if request.client else "?", body.username.lower())
    _check_lock(key)
    user = db.query(User).filter(User.username == body.username).first()
    if user is None or not user.is_active or not verify_password(body.password, user.password_hash):
        _FAILURES[key].append(time.monotonic())
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    _FAILURES.pop(key, None)
    return TokenOut(access_token=create_access_token(user.username, user.role), user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user
