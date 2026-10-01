from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, Field


def _utc(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)  # SQLite returns naive datetimes; all stored values are UTC
    return dt


UTCDateTime = Annotated[datetime, AfterValidator(_utc)]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------- auth
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class UserOut(ORM):
    id: int
    username: str
    full_name: str
    role: str


# ---------------------------------------------------------------- cases & evidence
class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=5000)
    case_number: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_\-]{3,32}$")


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    status: str | None = Field(default=None, pattern=r"^(open|closed)$")


class ImageOut(ORM):
    id: int
    case_id: int
    original_filename: str
    size_bytes: int
    sha256: str
    format_hint: str
    validation_notes: list[str]
    is_demo: bool
    uploaded_at: UTCDateTime
    os_info: dict[str, Any]


class JobOut(ORM):
    id: int
    image_id: int
    status: str
    stage: str
    progress: int
    error: str | None
    options: dict[str, Any]
    created_at: UTCDateTime
    started_at: UTCDateTime | None
    completed_at: UTCDateTime | None
    hash_verified_before: bool | None
    hash_verified_after: bool | None
    overall_risk_score: int | None
    overall_risk_band: str | None
    volatility_version: str | None


class JobDetail(JobOut):
    summary: dict[str, Any]
    image: ImageOut
    case_id: int
    case_number: str
    case_title: str


class CaseOut(ORM):
    id: int
    case_number: str
    title: str
    description: str
    status: str
    is_demo: bool
    created_at: UTCDateTime
    updated_at: UTCDateTime
    investigator: UserOut | None = None


class CaseDetail(CaseOut):
    images: list[ImageOut]
    jobs: list[JobOut]


class CustodyOut(ORM):
    id: int
    action: str
    actor: str
    timestamp: UTCDateTime
    details: str
    sha256: str | None
    image_id: int | None
    job_id: int | None


class PluginRunOut(ORM):
    id: int
    plugin: str
    stage: str
    rationale: str
    args: list[str]
    status: str
    started_at: UTCDateTime | None
    ended_at: UTCDateTime | None
    duration_ms: int | None
    row_count: int
    error: str | None
    output_sha256: str | None


class AnalysisStart(BaseModel):
    yara: bool = True


# ---------------------------------------------------------------- artifacts
class ProcessOut(ORM):
    id: int
    pid: int
    ppid: int | None
    name: str
    path: str | None
    cmdline: str | None
    create_time: UTCDateTime | None
    exit_time: UTCDateTime | None
    threads: int | None
    handle_count: int | None
    session_id: int | None
    wow64: bool | None
    offset: str | None
    in_pslist: bool
    in_psscan: bool
    in_pstree: bool
    is_hidden_candidate: bool
    is_terminated: bool
    deep_scanned: bool
    risk_score: int
    risk_band: str
    risk_contributors: list[dict[str, Any]]


class ModuleOut(ORM):
    id: int
    pid: int
    name: str
    path: str | None
    base: str | None
    size: int | None
    load_time: UTCDateTime | None
    in_load: bool | None
    in_init: bool | None
    in_mem: bool | None
    is_suspicious: bool
    reason: str


class NetworkOut(ORM):
    id: int
    pid: int | None
    owner: str | None
    protocol: str
    local_addr: str | None
    local_port: int | None
    foreign_addr: str | None
    foreign_port: int | None
    state: str | None
    created: UTCDateTime | None
    is_external: bool
    is_suspicious: bool
    reason: str


class RegionOut(ORM):
    id: int
    pid: int
    process_name: str | None
    source: str
    start: str
    end: str
    protection: str | None
    tag: str | None
    private_memory: bool | None
    commit_charge: int | None
    mapped_file: str | None
    has_pe_header: bool
    hexdump: str | None
    disasm: str | None
    notes: str | None


class HandleOut(ORM):
    id: int
    pid: int
    handle_value: str | None
    handle_type: str | None
    granted_access: str | None
    name: str | None


class FindingOut(ORM):
    id: int
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: float
    finding: str
    evidence: list[dict[str, Any]]
    recommendation: str
    pid: int | None
    process_name: str | None
    process_id: int | None
    points: int
    attack_techniques: list[str]
    status: str


class FindingUpdate(BaseModel):
    status: str = Field(pattern=r"^(open|confirmed|false_positive|needs_review)$")


class ProcessDetail(BaseModel):
    process: ProcessOut
    parent: ProcessOut | None
    children: list[ProcessOut]
    modules: list[ModuleOut]
    network: list[NetworkOut]
    regions: list[RegionOut]
    handles: list[HandleOut]
    findings: list[FindingOut]
    sids: list[dict[str, Any]]
    privileges: list[dict[str, Any]]


class IOCOut(ORM):
    id: int
    ioc_type: str
    value: str
    source: str
    pid: int | None
    process_name: str | None
    confidence: str
    context: str
    watchlist_match: bool


class TimelineOut(ORM):
    id: int
    timestamp: UTCDateTime | None
    timestamp_source: str
    pid: int | None
    process_name: str | None
    event_type: str
    description: str
    evidence_ref: str | None
    severity: str


class YaraMatchOut(ORM):
    id: int
    pid: int | None
    process_name: str | None
    rule_name: str
    offset: str | None
    component: str | None
    matched_value: str | None
    severity: str


class YaraRuleOut(ORM):
    id: int
    filename: str
    sha256: str
    rule_names: list[str]
    builtin: bool
    enabled: bool
    uploaded_at: UTCDateTime


class ToggleIn(BaseModel):
    enabled: bool


class RuleOut(ORM):
    rule_id: str
    title: str
    category: str
    default_severity: str
    base_points: int
    description: str
    attack_techniques: list[str]
    enabled: bool


# ---------------------------------------------------------------- AI
class AIQuery(BaseModel):
    analysis_id: int
    question: str = Field(min_length=2, max_length=2000)


class AIAnswerOut(BaseModel):
    answer: str
    citations: list[dict[str, Any]]
    validation: dict[str, Any]
    provider: str
    intents: list[str]
    retrieved: int
    message_id: int | None = None


class ChatMessageOut(ORM):
    id: int
    role: str
    content: str
    citations: list[dict[str, Any]]
    validation: dict[str, Any]
    provider: str | None
    created_at: UTCDateTime


class ExplanationOut(BaseModel):
    finding_id: int
    provider: str
    model: str | None
    content: dict[str, Any]
    validation: dict[str, Any]
    grounded: bool
    created_at: UTCDateTime


class AISettingsIn(BaseModel):
    provider: str = Field(pattern=r"^(deterministic|openai|ollama)$")
    base_url: str = Field(default="", max_length=500)
    model: str = Field(default="", max_length=200)
    temperature: float = Field(default=0.1, ge=0, le=1)


class AISettingsOut(AISettingsIn):
    api_key_configured: bool


# ---------------------------------------------------------------- reports
class ReportRequest(BaseModel):
    analysis_id: int
    format: str = Field(pattern=r"^(pdf|html|json|csv)$")


class ReportOut(ORM):
    id: int
    job_id: int
    report_format: str
    sha256: str
    size_bytes: int
    generated_at: UTCDateTime


TokenOut.model_rebuild()
