from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_job, job_by_path
from app.core.database import get_db
from app.models import AIAnalysis, AnalysisJob, ChatMessage, User
from app.schemas.common import AIAnswerOut, AIQuery, ChatMessageOut
from app.services.ai.assistant import ForensicAssistant
from app.services.ai.providers import ChatMessageIn

router = APIRouter(prefix="/api/ai", tags=["AI assistant"])


@router.post("/query", response_model=AIAnswerOut)
def query(body: AIQuery, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> AIAnswerOut:
    """Ask the forensic assistant a question. Answers are grounded in retrieved evidence and validated."""
    job = job_by_path(body.analysis_id, db)
    if job.status not in ("completed", "completed_with_errors"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Analysis has not completed yet")
    history_rows = db.scalars(select(ChatMessage).where(ChatMessage.job_id == job.id)
                              .order_by(ChatMessage.id.desc()).limit(4)).all()
    history = [ChatMessageIn(m.role, m.content) for m in reversed(history_rows)]
    result = ForensicAssistant(db, job).ask(body.question, history)
    db.add(ChatMessage(job_id=job.id, user_id=user.id, role="user", content=body.question))
    msg = ChatMessage(job_id=job.id, user_id=user.id, role="assistant", content=result.answer,
                      citations=result.citations, validation=result.validation, provider=result.provider)
    db.add(msg)
    db.commit()
    return AIAnswerOut(answer=result.answer, citations=result.citations, validation=result.validation,
                       provider=result.provider, intents=result.intents, retrieved=result.retrieved,
                       message_id=msg.id)


@router.get("/history", response_model=list[ChatMessageOut])
def history(job: AnalysisJob = Depends(get_job), db: Session = Depends(get_db)):
    return list(db.scalars(select(ChatMessage).where(ChatMessage.job_id == job.id).order_by(ChatMessage.id)).all())


@router.get("/summary")
def summary(job: AnalysisJob = Depends(get_job), db: Session = Depends(get_db), regenerate: bool = False) -> dict:
    row = None if regenerate else db.scalar(select(AIAnalysis).where(
        AIAnalysis.job_id == job.id, AIAnalysis.kind == "case_summary").order_by(AIAnalysis.id.desc()))
    if row is None:
        if job.status not in ("completed", "completed_with_errors"):
            raise HTTPException(status.HTTP_409_CONFLICT, "Analysis has not completed yet")
        row = ForensicAssistant(db, job).case_summary()
    return {"markdown": row.content.get("markdown", ""), "provider": row.provider, "validation": row.validation,
            "created_at": row.created_at}
