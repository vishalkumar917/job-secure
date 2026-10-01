"""Background execution of analysis jobs.

A bounded ``ThreadPoolExecutor`` runs jobs outside the request cycle. Celery was
deliberately not used: a forensic workstation typically analyses one image at a
time, and a thread pool avoids running a broker (Redis/RabbitMQ) while still
keeping the API responsive. The Volatility work itself happens in child
processes, so the GIL is not a bottleneck. The ``JobRunner`` interface could be
swapped for Celery in a multi-node deployment.

Forensic integrity: the evidence SHA-256 is re-computed before and after the
analysis and compared with the intake hash; results are recorded in the chain
of custody.
"""

from __future__ import annotations

import dataclasses
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from app.core.config import Settings, get_settings
from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.models import AnalysisJob, RuleDefinition, YaraRuleFile
from app.services.ai.assistant import ForensicAssistant
from app.services.analysis.pipeline import AnalysisAborted, AnalysisPipeline
from app.services.analysis.sources import DemoSource, EvidenceSource, VolatilitySource
from app.services.detection.knowledge import cached_knowledge_base
from app.services.evidence.custody import record_custody
from app.services.evidence.storage import compute_evidence_hash
from app.services.volatility.runner import VolatilityRunner
from app.services.yara.manager import build_bundle

log = get_logger(__name__)


class JobRunner:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.executor = ThreadPoolExecutor(max_workers=max(1, self.settings.analysis_workers),
                                           thread_name_prefix="analysis")

    def submit(self, job_id: int) -> None:
        self.executor.submit(run_job, job_id)

    def shutdown(self) -> None:
        self.executor.shutdown(wait=False, cancel_futures=True)

    def recover(self) -> None:
        """Called at start-up: jobs left 'running' by a crash are failed; queued jobs are resubmitted."""
        db = SessionLocal()
        try:
            for job in db.scalars(select(AnalysisJob).where(AnalysisJob.status.in_(["running", "queued"]))).all():
                if job.status == "running":
                    job.status, job.error = "failed", "Interrupted by a server restart. Start the analysis again."
                    job.completed_at = datetime.now(timezone.utc)
                else:
                    self.submit(job.id)
            db.commit()
        finally:
            db.close()


def _build_source(settings: Settings, job: AnalysisJob, work_dir: Path) -> EvidenceSource:
    image = job.image
    if image.is_demo:
        return DemoSource(Path(image.stored_path))
    info = VolatilityRunner.detect(settings)
    return VolatilitySource(VolatilityRunner(settings, work_dir), Path(image.stored_path), info.get("version"))


def run_job(job_id: int) -> None:
    settings = get_settings()
    db = SessionLocal()
    job = db.get(AnalysisJob, job_id)
    if job is None:
        db.close()
        return
    image = job.image
    case_id = image.case_id
    actor = f"system (analysis job {job.id})"
    work_dir = settings.work_dir / f"job_{job.id}"
    try:
        job.status, job.stage, job.progress = "running", "integrity_check", 1
        job.started_at = datetime.now(timezone.utc)
        db.commit()
        record_custody(db, case_id=case_id, image_id=image.id, job_id=job.id, action="analysis_started",
                       actor=actor, details=f"Options: {job.options}")
        db.commit()

        if settings.verify_hash_on_analysis:
            current = compute_evidence_hash(Path(image.stored_path))
            job.hash_verified_before = current == image.sha256
            record_custody(db, case_id=case_id, image_id=image.id, job_id=job.id, action="integrity_verified",
                           actor=actor, sha256=current,
                           details="Pre-analysis SHA-256 " + ("matches" if job.hash_verified_before else
                                                              "DOES NOT MATCH") + " the intake hash.")
            db.commit()
            if not job.hash_verified_before:
                raise AnalysisAborted("Evidence integrity check failed: SHA-256 differs from the intake hash. "
                                      "Analysis was not performed.")

        source = _build_source(settings, job, work_dir)

        kb = cached_knowledge_base(str(settings.rules_dir))
        enabled = {r.rule_id for r in db.scalars(select(RuleDefinition).where(RuleDefinition.enabled)).all()}
        all_rules = db.scalars(select(RuleDefinition)).all()
        enabled_rules = enabled if all_rules else None

        yara_bundle = None
        if job.options.get("yara", True):
            files = [Path(f.stored_path) for f in
                     db.scalars(select(YaraRuleFile).where(YaraRuleFile.enabled)).all()]
            yara_bundle, severities = build_bundle(files, work_dir / "yara" / "bundle.yar")
            if severities:
                kb = dataclasses.replace(kb, yara_severity=severities)

        AnalysisPipeline(db, job, settings, source, kb, enabled_rules, yara_bundle).execute()

        job.stage, job.progress = "ai_summary", 97
        db.commit()
        try:
            ForensicAssistant(db, job).case_summary()
        except Exception:  # noqa: BLE001 - summary is not essential
            log.exception("case summary failed", extra={"analysis_id": job.id})

        if settings.verify_hash_on_analysis:
            after = compute_evidence_hash(Path(image.stored_path))
            job.hash_verified_after = after == image.sha256
            record_custody(db, case_id=case_id, image_id=image.id, job_id=job.id, action="integrity_verified",
                           actor=actor, sha256=after,
                           details="Post-analysis SHA-256 " + ("matches" if job.hash_verified_after else
                                                               "DOES NOT MATCH") + " the intake hash.")
        failures = (job.summary or {}).get("plugin_failures") or {}
        job.status = "completed_with_errors" if failures else "completed"
        job.stage, job.progress = "completed", 100
        job.completed_at = datetime.now(timezone.utc)
        record_custody(db, case_id=case_id, image_id=image.id, job_id=job.id, action="analysis_completed",
                       actor=actor, details=f"Status {job.status}; overall risk {job.overall_risk_score} "
                                            f"({job.overall_risk_band}); plugin failures: {len(failures)}")
        db.commit()
        log.info("analysis completed", extra={"analysis_id": job.id, "status": job.status})
    except Exception as exc:  # noqa: BLE001 - always leave the job in a terminal state
        db.rollback()
        job = db.get(AnalysisJob, job_id)
        message = str(exc) if isinstance(exc, AnalysisAborted) else f"Unexpected error: {type(exc).__name__}: {exc}"
        if job is not None:
            job.status, job.error = "failed", message
            job.completed_at = datetime.now(timezone.utc)
            record_custody(db, case_id=case_id, image_id=image.id, job_id=job.id, action="analysis_failed",
                           actor=actor, details=message[:1000])
            db.commit()
        log.error("analysis failed", extra={"analysis_id": job_id, "error": message})
    finally:
        db.close()
        if not settings.environment.startswith("dev"):
            # Keep raw plugin output in development for inspection; in production keep only JSON outputs.
            shutil.rmtree(work_dir / "yara", ignore_errors=True)


_runner: JobRunner | None = None


def get_job_runner() -> JobRunner:
    global _runner
    if _runner is None:
        _runner = JobRunner()
    return _runner
