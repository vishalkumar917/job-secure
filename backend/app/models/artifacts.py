"""Forensic artifacts extracted from a memory image and the analytical results derived from them.

Every artifact row belongs to an ``analysis_jobs`` row so that re-running an
analysis (e.g. with new symbols or rules) never mixes results.
Memory addresses are stored as hex strings because 64-bit kernel addresses
overflow signed 64-bit integer columns.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.case import utcnow


def _job_fk() -> Mapped[int]:
    return mapped_column(ForeignKey("analysis_jobs.id", ondelete="CASCADE"), index=True)


def _proc_fk() -> Mapped[int | None]:
    return mapped_column(ForeignKey("processes.id", ondelete="SET NULL"), index=True)


class Process(Base):
    __tablename__ = "processes"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = _job_fk()
    pid: Mapped[int] = mapped_column(Integer)
    ppid: Mapped[int | None] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(255))
    path: Mapped[str | None] = mapped_column(Text)
    cmdline: Mapped[str | None] = mapped_column(Text)
    create_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exit_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    threads: Mapped[int | None] = mapped_column(Integer)
    handle_count: Mapped[int | None] = mapped_column(Integer)
    session_id: Mapped[int | None] = mapped_column(Integer)
    wow64: Mapped[bool | None] = mapped_column(Boolean)
    offset: Mapped[str | None] = mapped_column(String(32))
    in_pslist: Mapped[bool] = mapped_column(Boolean, default=False)
    in_psscan: Mapped[bool] = mapped_column(Boolean, default=False)
    in_pstree: Mapped[bool] = mapped_column(Boolean, default=False)
    is_hidden_candidate: Mapped[bool] = mapped_column(Boolean, default=False)
    is_terminated: Mapped[bool] = mapped_column(Boolean, default=False)
    user_sids: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    privileges: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    deep_scanned: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_band: Mapped[str] = mapped_column(String(16), default="low")
    risk_contributors: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)


Index("ix_process_job_pid", Process.job_id, Process.pid)
Index("ix_process_job_risk", Process.job_id, Process.risk_score)


class ProcessRelationship(Base):
    __tablename__ = "process_relationships"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = _job_fk()
    parent_process_id: Mapped[int | None] = mapped_column(ForeignKey("processes.id", ondelete="CASCADE"))
    child_process_id: Mapped[int] = mapped_column(ForeignKey("processes.id", ondelete="CASCADE"))
    parent_pid: Mapped[int | None] = mapped_column(Integer)
    child_pid: Mapped[int] = mapped_column(Integer)
    is_anomalous: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str] = mapped_column(Text, default="")


class Module(Base):
    __tablename__ = "modules"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = _job_fk()
    process_id: Mapped[int | None] = _proc_fk()
    pid: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(255))
    path: Mapped[str | None] = mapped_column(Text)
    base: Mapped[str | None] = mapped_column(String(32))
    size: Mapped[int | None] = mapped_column(Integer)
    load_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    in_load: Mapped[bool | None] = mapped_column(Boolean)  # from ldrmodules (targeted)
    in_init: Mapped[bool | None] = mapped_column(Boolean)
    in_mem: Mapped[bool | None] = mapped_column(Boolean)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str] = mapped_column(Text, default="")


Index("ix_module_job_pid", Module.job_id, Module.pid)


class NetworkConnection(Base):
    __tablename__ = "network_connections"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = _job_fk()
    process_id: Mapped[int | None] = _proc_fk()
    pid: Mapped[int | None] = mapped_column(Integer)
    owner: Mapped[str | None] = mapped_column(String(255))
    protocol: Mapped[str] = mapped_column(String(16))
    local_addr: Mapped[str | None] = mapped_column(String(64))
    local_port: Mapped[int | None] = mapped_column(Integer)
    foreign_addr: Mapped[str | None] = mapped_column(String(64))
    foreign_port: Mapped[int | None] = mapped_column(Integer)
    state: Mapped[str | None] = mapped_column(String(32))
    created: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    offset: Mapped[str | None] = mapped_column(String(32))
    is_external: Mapped[bool] = mapped_column(Boolean, default=False)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str] = mapped_column(Text, default="")


class MemoryRegion(Base):
    __tablename__ = "memory_regions"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = _job_fk()
    process_id: Mapped[int | None] = _proc_fk()
    pid: Mapped[int] = mapped_column(Integer)
    process_name: Mapped[str | None] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(32))  # malfind | vadinfo
    start: Mapped[str] = mapped_column(String(32))
    end: Mapped[str] = mapped_column(String(32))
    protection: Mapped[str | None] = mapped_column(String(64))
    tag: Mapped[str | None] = mapped_column(String(16))
    private_memory: Mapped[bool | None] = mapped_column(Boolean)
    commit_charge: Mapped[int | None] = mapped_column(Integer)
    mapped_file: Mapped[str | None] = mapped_column(Text)
    has_pe_header: Mapped[bool] = mapped_column(Boolean, default=False)
    hexdump: Mapped[str | None] = mapped_column(Text)
    disasm: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)


Index("ix_region_job_pid", MemoryRegion.job_id, MemoryRegion.pid)


class HandleRecord(Base):
    __tablename__ = "handles"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = _job_fk()
    process_id: Mapped[int | None] = _proc_fk()
    pid: Mapped[int] = mapped_column(Integer)
    handle_value: Mapped[str | None] = mapped_column(String(32))
    handle_type: Mapped[str | None] = mapped_column(String(64))
    granted_access: Mapped[str | None] = mapped_column(String(32))
    name: Mapped[str | None] = mapped_column(Text)


class YaraMatch(Base):
    __tablename__ = "yara_matches"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = _job_fk()
    process_id: Mapped[int | None] = _proc_fk()
    pid: Mapped[int | None] = mapped_column(Integer)
    process_name: Mapped[str | None] = mapped_column(String(255))
    rule_name: Mapped[str] = mapped_column(String(255))
    offset: Mapped[str | None] = mapped_column(String(32))
    component: Mapped[str | None] = mapped_column(String(255))
    matched_value: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default="medium")


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = _job_fk()
    process_id: Mapped[int | None] = _proc_fk()
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(64))
    pid: Mapped[int | None] = mapped_column(Integer)
    process_name: Mapped[str | None] = mapped_column(String(255))
    confidence: Mapped[str] = mapped_column(String(16))  # low | medium | high
    context: Mapped[str] = mapped_column(Text, default="")
    watchlist_match: Mapped[bool] = mapped_column(Boolean, default=False)


class RuleDefinition(Base):
    __tablename__ = "rules"

    rule_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(32))
    default_severity: Mapped[str] = mapped_column(String(16))
    base_points: Mapped[int] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(Text)
    attack_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = _job_fk()
    process_id: Mapped[int | None] = _proc_fk()
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    finding: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    recommendation: Mapped[str] = mapped_column(Text, default="")
    pid: Mapped[int | None] = mapped_column(Integer)
    process_name: Mapped[str | None] = mapped_column(String(255))
    points: Mapped[int] = mapped_column(Integer, default=0)
    attack_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="open")  # open | confirmed | false_positive | needs_review
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = _job_fk()
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    timestamp_source: Mapped[str] = mapped_column(String(128))
    pid: Mapped[int | None] = mapped_column(Integer)
    process_name: Mapped[str | None] = mapped_column(String(255))
    event_type: Mapped[str] = mapped_column(String(48))
    description: Mapped[str] = mapped_column(Text)
    evidence_ref: Mapped[str | None] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16), default="info")


class AIAnalysis(Base):
    __tablename__ = "ai_analysis"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = _job_fk()
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))  # finding_explanation | case_summary | process_summary
    subject: Mapped[str | None] = mapped_column(String(64))
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str | None] = mapped_column(String(128))
    content: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    validation: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    grounded: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = _job_fk()
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    role: Mapped[str] = mapped_column(String(16))  # user | assistant
    content: Mapped[str] = mapped_column(Text)
    citations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    validation: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    provider: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class YaraRuleFile(Base):
    __tablename__ = "yara_rule_files"

    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    stored_path: Mapped[str] = mapped_column(String(1024))
    sha256: Mapped[str] = mapped_column(String(64))
    rule_names: Mapped[list[str]] = mapped_column(JSON, default=list)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    uploaded_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = _job_fk()
    report_format: Mapped[str] = mapped_column(String(8))  # pdf | html | json | csv
    path: Mapped[str] = mapped_column(String(1024))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    generated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


Index("ix_finding_job_sev", Finding.job_id, Finding.severity)
Index("ix_ioc_job_type", IOC.job_id, IOC.ioc_type)
Index("ix_net_job_pid", NetworkConnection.job_id, NetworkConnection.pid)
