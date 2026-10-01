"""Collects all report content for one analysis into a single serialisable structure."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    IOC,
    AIAnalysis,
    AnalysisJob,
    CustodyEvent,
    Finding,
    MemoryRegion,
    NetworkConnection,
    PluginRun,
    Process,
    TimelineEvent,
    YaraMatch,
)
from app.services.ai.evidence import SEV_RANK
from app.services.volatility.plugins import PLUGINS

METHODOLOGY = [
    "Evidence intake: the memory image was hashed (SHA-256) on upload, stored read-only, and re-hashed before and "
    "after analysis to verify integrity.",
    "Identification: Volatility 3 windows.info located the kernel and resolved symbols to identify the OS build.",
    "Process enumeration: pslist (OS view), psscan (pool scanning) and pstree were cross-viewed to detect hidden "
    "and terminated processes and to reconstruct ancestry.",
    "Execution context: command lines (cmdline) and loaded modules (dlllist) were extracted.",
    "Network: netscan recovered TCP/UDP endpoints with owning processes.",
    "Injection: malfind identified private executable memory; targeted vadinfo/ldrmodules provided corroboration.",
    "Triage: a first detection pass ranked processes; expensive plugins (vadinfo, ldrmodules, handles, getsids, "
    "privileges, optional YARA) were run only for the highest-risk processes.",
    "Detection: a modular rule engine evaluated the evidence against documented baselines and heuristics.",
    "Scoring: an explainable additive model with per-category caps produced process risk scores.",
    "IOC extraction and timeline construction were performed on the structured evidence.",
    "AI assistance: explanations were generated from retrieved evidence only and validated against the evidence "
    "store; a deterministic engine is used when no LLM is configured.",
]

LIMITATIONS = [
    "Memory analysis captures a single point in time; activity before acquisition may not be resident in memory.",
    "Live acquisition can introduce smear (inconsistent structures), which may cause false cross-view discrepancies.",
    "Paged-out memory is not present in a RAM image; command lines, modules or regions may be missing.",
    "Detection rules are heuristics and signatures. A finding is an indicator requiring corroboration, not proof of "
    "malicious activity.",
    "The risk score is this project's analytical prioritisation model, not an authoritative malware verdict.",
    "Remote IP addresses and domains are not asserted to be malicious without external threat-intelligence context.",
    "AI-generated text is constrained to stored evidence and validated, but must be reviewed by the investigator.",
]


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def build_report_data(db: Session, job: AnalysisJob, generated_by: str) -> dict[str, Any]:
    image = job.image
    case = image.case
    jid = job.id
    procs = db.scalars(select(Process).where(Process.job_id == jid).order_by(Process.risk_score.desc())).all()
    findings = sorted(db.scalars(select(Finding).where(Finding.job_id == jid)).all(),
                      key=lambda f: (-SEV_RANK.get(f.severity, 0), -f.confidence))
    net = db.scalars(select(NetworkConnection).where(NetworkConnection.job_id == jid)).all()
    regions = db.scalars(select(MemoryRegion).where(MemoryRegion.job_id == jid, MemoryRegion.source == "malfind")).all()
    iocs = db.scalars(select(IOC).where(IOC.job_id == jid)).all()
    yara = db.scalars(select(YaraMatch).where(YaraMatch.job_id == jid)).all()
    timeline = db.scalars(select(TimelineEvent).where(TimelineEvent.job_id == jid)
                          .order_by(TimelineEvent.timestamp)).all()
    plugins = db.scalars(select(PluginRun).where(PluginRun.job_id == jid).order_by(PluginRun.id)).all()
    custody = db.scalars(select(CustodyEvent).where(CustodyEvent.case_id == case.id)
                         .order_by(CustodyEvent.timestamp)).all()
    summary_ai = db.scalar(select(AIAnalysis).where(AIAnalysis.job_id == jid, AIAnalysis.kind == "case_summary")
                           .order_by(AIAnalysis.id.desc()))
    explanations = {a.finding_id: a for a in db.scalars(select(AIAnalysis).where(
        AIAnalysis.job_id == jid, AIAnalysis.kind == "finding_explanation")).all()}
    s = job.summary or {}
    suspicious = [p for p in procs if p.risk_score >= 30]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": generated_by,
        "is_demo": image.is_demo,
        "case": {"id": case.id, "number": case.case_number, "title": case.title, "description": case.description,
                 "investigator": case.investigator.username if case.investigator else None, "status": case.status},
        "image": {"id": image.id, "filename": image.original_filename, "size_bytes": image.size_bytes,
                  "sha256": image.sha256, "format": image.format_hint, "uploaded_at": _iso(image.uploaded_at),
                  "validation_notes": image.validation_notes, "os_info": image.os_info},
        "analysis": {"id": jid, "status": job.status, "started_at": _iso(job.started_at),
                     "completed_at": _iso(job.completed_at), "volatility_version": job.volatility_version,
                     "hash_verified_before": job.hash_verified_before, "hash_verified_after": job.hash_verified_after,
                     "overall_risk_score": job.overall_risk_score, "overall_risk_band": job.overall_risk_band},
        "summary": s,
        "executive_summary": (summary_ai.content.get("markdown") if summary_ai else None),
        "executive_summary_provider": summary_ai.provider if summary_ai else None,
        "methodology": METHODOLOGY,
        "plugins": [{"plugin": p.plugin, "stage": p.stage, "status": p.status, "args": " ".join(p.args or []),
                     "duration_ms": p.duration_ms, "rows": p.row_count, "error": p.error,
                     "rationale": PLUGINS.get(p.plugin).rationale if p.plugin in PLUGINS else p.rationale,
                     "output_sha256": p.output_sha256} for p in plugins],
        "processes": [{"pid": p.pid, "ppid": p.ppid, "name": p.name, "path": p.path, "cmdline": p.cmdline,
                       "create_time": _iso(p.create_time), "exit_time": _iso(p.exit_time),
                       "sources": [n for n, f in (("pslist", p.in_pslist), ("psscan", p.in_psscan),
                                                  ("pstree", p.in_pstree)) if f],
                       "hidden": p.is_hidden_candidate, "risk_score": p.risk_score, "risk_band": p.risk_band,
                       "contributors": p.risk_contributors} for p in procs],
        "suspicious_processes": [p.id for p in suspicious],
        "findings": [{"id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
                      "category": f.category, "confidence": f.confidence, "finding": f.finding, "pid": f.pid,
                      "process_name": f.process_name, "evidence": f.evidence, "recommendation": f.recommendation,
                      "attack": f.attack_techniques, "status": f.status,
                      "explanation": explanations[f.id].content if f.id in explanations else None}
                     for f in findings],
        "memory_regions": [{"pid": r.pid, "process": r.process_name, "start": r.start, "end": r.end,
                            "protection": r.protection, "tag": r.tag, "private": r.private_memory,
                            "pe_header": r.has_pe_header,
                            "first_line": (r.hexdump or "").splitlines()[0] if r.hexdump else None} for r in regions],
        "network": [{"pid": c.pid, "owner": c.owner, "protocol": c.protocol, "local": f"{c.local_addr}:{c.local_port}",
                     "foreign": f"{c.foreign_addr}:{c.foreign_port}", "state": c.state, "created": _iso(c.created),
                     "external": c.is_external, "suspicious": c.is_suspicious, "reason": c.reason} for c in net],
        "iocs": [{"type": i.ioc_type, "value": i.value, "source": i.source, "pid": i.pid,
                  "process": i.process_name, "confidence": i.confidence, "context": i.context,
                  "watchlist": i.watchlist_match} for i in iocs],
        "yara": [{"rule": y.rule_name, "pid": y.pid, "process": y.process_name, "offset": y.offset,
                  "component": y.component, "value": y.matched_value, "severity": y.severity} for y in yara],
        "timeline": [{"timestamp": _iso(t.timestamp), "timestamp_source": t.timestamp_source, "pid": t.pid,
                      "process": t.process_name, "event": t.event_type, "description": t.description,
                      "severity": t.severity, "ref": t.evidence_ref} for t in timeline],
        "custody": [{"timestamp": _iso(c.timestamp), "action": c.action, "actor": c.actor, "details": c.details,
                     "sha256": c.sha256} for c in custody],
        "limitations": LIMITATIONS + [f"Plugin '{k}' did not complete: {v}" for k, v in
                                      (s.get("plugin_failures") or {}).items()]
                       + [f"Rule {k} not evaluated: {v}" for k, v in (s.get("rules_not_evaluated") or {}).items()
                          if "disabled" not in v],
        "next_steps": _next_steps(findings),
        "scoring_model": s.get("scoring_model"),
    }


def _next_steps(findings: list[Finding]) -> list[str]:
    steps: list[str] = []
    for f in findings:
        if SEV_RANK.get(f.severity, 0) >= 2 and f.recommendation and f.recommendation not in steps:
            steps.append(f.recommendation)
    steps.append("Correlate memory findings with disk images, Windows event logs, EDR telemetry and network logs.")
    steps.append("Preserve this report, the evidence hash and the raw plugin outputs with the case file.")
    return steps[:15]
