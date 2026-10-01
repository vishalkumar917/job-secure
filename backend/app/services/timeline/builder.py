"""Forensic timeline construction from timestamped artifacts.

Only timestamps that exist in memory structures are used (EPROCESS
CreateTime/ExitTime, TCP endpoint creation time, LDR load time). Findings have
no intrinsic time; they are anchored to the owning process creation time and
labelled as such, or listed as "timestamp unavailable".
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.services.detection.base import AnalysisContext, FindingDraft


@dataclass
class TimelineDraft:
    timestamp: datetime | None
    timestamp_source: str
    pid: int | None
    process_name: str | None
    event_type: str
    description: str
    severity: str
    evidence_ref: str | None = None


def build_timeline(ctx: AnalysisContext, findings: list[FindingDraft],
                   process_bands: dict[str, str]) -> list[TimelineDraft]:
    events: list[TimelineDraft] = []
    sev_for_band = {"critical": "critical", "high": "high", "moderate": "medium", "low": "info"}

    for p in ctx.processes:
        sev = sev_for_band.get(process_bands.get(p.key, "low"), "info")
        if p.create_time:
            hidden = " (not in active process list)" if p.is_hidden_candidate else ""
            events.append(TimelineDraft(p.create_time, "EPROCESS.CreateTime", p.pid, p.name, "process_created",
                                        f"{p.name} started (PPID {p.ppid}){hidden}", sev, f"PROC:{p.pid}"))
        if p.exit_time:
            events.append(TimelineDraft(p.exit_time, "EPROCESS.ExitTime", p.pid, p.name, "process_exited",
                                        f"{p.name} exited", "info", f"PROC:{p.pid}"))

    for idx, c in enumerate(ctx.evidence.network):
        if c.created is None:
            continue
        flagged = ctx.flagged_connections.get(idx)
        events.append(TimelineDraft(
            c.created, "TCP endpoint creation time", c.pid, c.owner, "network_connection",
            f"{c.protocol} {c.local_addr}:{c.local_port} -> {c.foreign_addr}:{c.foreign_port} {c.state or ''}".strip()
            + (f" [{'; '.join(flagged)}]" if flagged else ""), "medium" if flagged else "info", f"NET:{idx}"))

    flagged_paths = {k for k in ctx.flagged_modules}
    for pid, mods in ctx.modules_by_pid.items():
        for m in mods:
            if m.load_time and (pid, (m.path or "").lower()) in flagged_paths:
                events.append(TimelineDraft(m.load_time, "LDR_DATA_TABLE_ENTRY.LoadTime", pid, m.process,
                                            "module_loaded", f"Suspicious module loaded: {m.path}", "medium",
                                            f"MOD:{pid}:{m.base}"))

    by_key = {p.key: p for p in ctx.processes}
    for i, f in enumerate(findings):
        if f.severity not in ("medium", "high", "critical"):
            continue
        proc = by_key.get(f.process_key or "")
        ts = proc.create_time if proc else None
        events.append(TimelineDraft(
            ts, "anchored to process creation time (finding has no intrinsic timestamp)" if ts else "timestamp unavailable",
            f.pid, f.process_name, _event_type(f), f"{f.title}: {f.finding[:240]}", f.severity, f"FINDING:{i}"))

    events.sort(key=lambda e: (e.timestamp is None, e.timestamp.timestamp() if e.timestamp else 0.0))
    return events


def _event_type(f: FindingDraft) -> str:
    return {"memory": "memory_injection_indicator", "commandline": "suspicious_command",
            "network": "suspicious_network", "ioc": "ioc_match", "yara": "yara_match"}.get(f.category, "finding")
