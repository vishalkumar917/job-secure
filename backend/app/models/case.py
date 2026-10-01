"""Users, cases, evidence images, analysis jobs, plugin runs and chain of custody."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, BigInteger
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32), default="investigator")  # admin | investigator
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_number: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | closed
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    investigator_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    investigator: Mapped[User | None] = relationship()
    images: Mapped[list[MemoryImage]] = relationship(back_populates="case", cascade="all, delete-orphan")


class MemoryImage(Base):
    __tablename__ = "memory_images"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    original_filename: Mapped[str] = mapped_column(String(255))
    stored_path: Mapped[str] = mapped_column(String(1024))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    format_hint: Mapped[str] = mapped_column(String(32), default="raw")  # raw | crashdump | vmware | demo
    validation_notes: Mapped[list[str]] = mapped_column(JSON, default=list)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    uploaded_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Filled after windows.info: os name, build, architecture, kernel base, symbols, confidence
    os_info: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    case: Mapped[Case] = relationship(back_populates="images")
    jobs: Mapped[list[AnalysisJob]] = relationship(back_populates="image", cascade="all, delete-orphan")


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    image_id: Mapped[int] = mapped_column(ForeignKey("memory_images.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    stage: Mapped[str] = mapped_column(String(64), default="queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    hash_verified_before: Mapped[bool | None] = mapped_column(Boolean)
    hash_verified_after: Mapped[bool | None] = mapped_column(Boolean)
    overall_risk_score: Mapped[int | None] = mapped_column(Integer)
    overall_risk_band: Mapped[str | None] = mapped_column(String(16))
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    volatility_version: Mapped[str | None] = mapped_column(String(64))

    image: Mapped[MemoryImage] = relationship(back_populates="jobs")
    plugin_runs: Mapped[list[PluginRun]] = relationship(
        back_populates="job", cascade="all, delete-orphan", order_by="PluginRun.id"
    )


class PluginRun(Base):
    """One Volatility plugin execution - the analysis log required for reproducibility."""

    __tablename__ = "plugin_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("analysis_jobs.id", ondelete="CASCADE"), index=True)
    plugin: Mapped[str] = mapped_column(String(64))
    stage: Mapped[str] = mapped_column(String(64))
    rationale: Mapped[str] = mapped_column(Text, default="")
    args: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16))  # success | failed | timeout | skipped
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    output_path: Mapped[str | None] = mapped_column(String(1024))
    output_sha256: Mapped[str | None] = mapped_column(String(64))

    job: Mapped[AnalysisJob] = relationship(back_populates="plugin_runs")


class CustodyEvent(Base):
    __tablename__ = "custody_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    image_id: Mapped[int | None] = mapped_column(ForeignKey("memory_images.id", ondelete="SET NULL"))
    job_id: Mapped[int | None] = mapped_column(ForeignKey("analysis_jobs.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    details: Mapped[str] = mapped_column(Text, default="")
    sha256: Mapped[str | None] = mapped_column(String(64))


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


Index("ix_custody_case_time", CustodyEvent.case_id, CustodyEvent.timestamp)
