"""Evidence Store: turns persisted forensic artifacts into citable evidence documents.

Each document has a stable ID (``F-12``, ``PROC-4528``, ``NET-7``, ``MEM-3``,
``MOD-90``, ``IOC-4``, ``YARA-1``, ``TL-55``, ``SUMMARY``). The LLM only ever
sees these documents - never the raw memory image - and must cite their IDs.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    IOC,
    AnalysisJob,
    Finding,
    MemoryRegion,
    Module,
    NetworkConnection,
    Process,
    TimelineEvent,
    YaraMatch,
)

_TOKEN = re.compile(r"[a-z0-9_.\\:-]+")
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def tokenize(text: str) -> list[str]:
    toks = _TOKEN.findall(text.lower())
    out = []
    for t in toks:
        out.append(t)
        if "." in t or "\\" in t:
            out.extend(p for p in re.split(r"[.\\]", t) if len(p) > 2)
    return out


def fmt_dt(dt) -> str:
    if dt is None:
        return "unknown"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


@dataclass
class EvidenceDoc:
    id: str
    kind: str
    title: str
    text: str
    pid: int | None = None
    severity: str = "info"
    rank: float = 0.0  # intrinsic importance (risk score / severity)
    data: dict[str, Any] = field(default_factory=dict)
    tokens: Counter = field(default_factory=Counter)


@dataclass
class EvidenceCorpus:
    job: AnalysisJob
    docs: dict[str, EvidenceDoc]
    by_pid: dict[int, list[str]]
    pids: set[int]
    process_names: set[str]
    blob: str  # lower-cased concatenation used by the validator

    @property
    def ids(self) -> set[str]:
        return set(self.docs)

    def process_doc(self, pid: int) -> EvidenceDoc | None:
        return self.docs.get(f"PROC-{pid}")


class EvidenceStore:
    """Loads all evidence for one analysis job from the database."""

    def __init__(self, db: Session):
        self.db = db

    def load(self, job: AnalysisJob) -> EvidenceCorpus:
        db, jid = self.db, job.id
        docs: dict[str, EvidenceDoc] = {}
        by_pid: dict[int, list[str]] = defaultdict(list)

        def add(doc: EvidenceDoc) -> None:
            doc.tokens = Counter(tokenize(doc.title + " " + doc.text))
            docs[doc.id] = doc
            if doc.pid is not None:
                by_pid[doc.pid].append(doc.id)

        procs = db.scalars(select(Process).where(Process.job_id == jid)).all()
        pid_counts = Counter(p.pid for p in procs)
        proc_ids: dict[int, str] = {}
        for p in sorted(procs, key=lambda x: (x.is_terminated, x.id)):
            pid_id = f"PROC-{p.pid}" if f"PROC-{p.pid}" not in docs else f"PROC-{p.pid}.{p.id}"
            proc_ids[p.id] = pid_id
            parent = next((q for q in procs if q.pid == p.ppid and not q.is_terminated), None)
            contributors = ", ".join(f"{c['points']:+d} {c['label']}" for c in p.risk_contributors or [])
            flags = []
            if p.is_hidden_candidate:
                flags.append("found by psscan but NOT in pslist (hidden candidate)")
            if p.is_terminated:
                flags.append(f"terminated at {fmt_dt(p.exit_time)}")
            if pid_counts[p.pid] > 1:
                flags.append("PID reused by another process in this image")
            text = (f"Process {p.name} PID {p.pid} PPID {p.ppid}"
                    f"{' (parent ' + parent.name + ')' if parent else ' (parent not present in memory)'}; "
                    f"path: {p.path or 'unknown'}; command line: {p.cmdline or 'not recovered'}; "
                    f"created: {fmt_dt(p.create_time)}; risk score {p.risk_score} ({p.risk_band})"
                    f"{'; contributors: ' + contributors if contributors else ''}; "
                    f"sources: {', '.join(s for s, f in (('pslist', p.in_pslist), ('psscan', p.in_psscan), ('pstree', p.in_pstree)) if f)}"
                    f"{'; ' + '; '.join(flags) if flags else ''}")
            add(EvidenceDoc(pid_id, "process", f"{p.name} (PID {p.pid})", text, p.pid,
                            "high" if p.risk_score >= 60 else "medium" if p.risk_score >= 30 else "info",
                            float(p.risk_score), {"name": p.name, "pid": p.pid, "ppid": p.ppid,
                                                  "risk_score": p.risk_score, "risk_band": p.risk_band,
                                                  "parent": parent.name if parent else None, "path": p.path,
                                                  "cmdline": p.cmdline, "contributors": p.risk_contributors,
                                                  "hidden": p.is_hidden_candidate, "terminated": p.is_terminated,
                                                  "create_time": fmt_dt(p.create_time)}))

        for f in db.scalars(select(Finding).where(Finding.job_id == jid)).all():
            ev = "; ".join(f"{e.get('description')}: {e.get('value')} ({e.get('source')})" for e in f.evidence[:6])
            text = (f"[{f.severity.upper()}] {f.rule_id} - {f.title}. {f.finding} Evidence: {ev}. "
                    f"Confidence {f.confidence:.2f}. Recommendation: {f.recommendation}")
            add(EvidenceDoc(f"F-{f.id}", "finding", f.title, text, f.pid, f.severity,
                            SEV_RANK.get(f.severity, 0) * 25 + f.confidence * 10,
                            {"rule_id": f.rule_id, "severity": f.severity, "confidence": f.confidence,
                             "finding": f.finding, "category": f.category, "process_name": f.process_name,
                             "pid": f.pid, "recommendation": f.recommendation, "evidence": f.evidence,
                             "status": f.status, "attack": f.attack_techniques}))

        for c in db.scalars(select(NetworkConnection).where(NetworkConnection.job_id == jid)).all():
            text = (f"{c.protocol} {c.local_addr}:{c.local_port} -> {c.foreign_addr}:{c.foreign_port} state "
                    f"{c.state or 'n/a'} owner {c.owner} PID {c.pid}; created {fmt_dt(c.created)}; "
                    f"{'external' if c.is_external else 'internal/local'}"
                    f"{'; SUSPICIOUS: ' + c.reason if c.is_suspicious else ''}")
            add(EvidenceDoc(f"NET-{c.id}", "network", f"Connection {c.foreign_addr}:{c.foreign_port}", text, c.pid,
                            "medium" if c.is_suspicious else "info", 20.0 if c.is_suspicious else 1.0,
                            {"owner": c.owner, "pid": c.pid, "foreign": f"{c.foreign_addr}:{c.foreign_port}",
                             "local": f"{c.local_addr}:{c.local_port}", "state": c.state, "protocol": c.protocol,
                             "suspicious": c.is_suspicious, "reason": c.reason, "external": c.is_external}))

        for r in db.scalars(select(MemoryRegion).where(MemoryRegion.job_id == jid)).all():
            first = (r.hexdump or "").splitlines()[0][:60] if r.hexdump else "n/a"
            text = (f"{r.source} region in {r.process_name} PID {r.pid}: {r.start}-{r.end} protection {r.protection} "
                    f"tag {r.tag} private={r.private_memory} PE header={'yes' if r.has_pe_header else 'no'}; "
                    f"first bytes: {first}")
            add(EvidenceDoc(f"MEM-{r.id}", "memory_region", f"{r.source} region {r.start}", text, r.pid,
                            "high" if r.has_pe_header else "medium", 15.0 if r.source == "malfind" else 3.0,
                            {"source": r.source, "start": r.start, "end": r.end, "protection": r.protection,
                             "pe": r.has_pe_header, "process_name": r.process_name, "pid": r.pid,
                             "private": r.private_memory}))

        mods_by_pid: dict[int, list[Module]] = defaultdict(list)
        for m in db.scalars(select(Module).where(Module.job_id == jid)).all():
            mods_by_pid[m.pid].append(m)
            if m.is_suspicious:
                add(EvidenceDoc(f"MOD-{m.id}", "module", m.name,
                                f"Module {m.name} path {m.path} loaded in PID {m.pid}; suspicious: {m.reason}",
                                m.pid, "medium", 12.0, {"name": m.name, "path": m.path, "pid": m.pid,
                                                        "reason": m.reason}))

        for i in db.scalars(select(IOC).where(IOC.job_id == jid)).all():
            add(EvidenceDoc(f"IOC-{i.id}", "ioc", f"{i.ioc_type} {i.value[:60]}",
                            f"IOC {i.ioc_type} '{i.value}' from {i.source} (process {i.process_name} PID {i.pid}); "
                            f"confidence {i.confidence}; {i.context}"
                            f"{'; on local watchlist' if i.watchlist_match else ''}",
                            i.pid, "medium" if i.confidence == "high" else "info",
                            {"high": 10.0, "medium": 5.0, "low": 1.0}.get(i.confidence, 1.0),
                            {"type": i.ioc_type, "value": i.value, "confidence": i.confidence, "source": i.source,
                             "pid": i.pid, "process_name": i.process_name}))

        for y in db.scalars(select(YaraMatch).where(YaraMatch.job_id == jid)).all():
            add(EvidenceDoc(f"YARA-{y.id}", "yara", y.rule_name,
                            f"YARA rule {y.rule_name} matched in {y.process_name} PID {y.pid} at offset {y.offset}",
                            y.pid, y.severity, 15.0, {"rule": y.rule_name, "pid": y.pid, "offset": y.offset}))

        for t in db.scalars(select(TimelineEvent).where(TimelineEvent.job_id == jid)
                            .order_by(TimelineEvent.timestamp)).all():
            if t.severity == "info" and t.event_type in ("process_created", "process_exited"):
                continue  # benign process lifecycle events are covered by the process documents
            add(EvidenceDoc(f"TL-{t.id}", "timeline", t.event_type,
                            f"{fmt_dt(t.timestamp)} ({t.timestamp_source}) {t.event_type}: {t.description} "
                            f"[PID {t.pid}]", t.pid, t.severity, 2.0,
                            {"timestamp": fmt_dt(t.timestamp), "event_type": t.event_type,
                             "description": t.description, "pid": t.pid, "ref": t.evidence_ref,
                             "timestamp_source": t.timestamp_source}))

        # Per-process module summaries so "which DLLs does PID X load" is answerable.
        for pid, mods in mods_by_pid.items():
            key = f"PROC-{pid}"
            if key in docs:
                names = ", ".join(m.name for m in mods[:40])
                docs[key].data["modules"] = [m.name for m in mods]
                docs[key].text += f"; {len(mods)} loaded modules: {names}{' ...' if len(mods) > 40 else ''}"
                docs[key].tokens = Counter(tokenize(docs[key].title + " " + docs[key].text))

        s = job.summary or {}
        image = job.image
        os_info = image.os_info or {}
        summary_text = (
            f"Analysis {job.id} of image '{image.original_filename}' SHA-256 {image.sha256}. "
            f"{'SYNTHETIC DEMO DATA - not real forensic evidence. ' if image.is_demo else ''}"
            f"OS: {os_info.get('os_name') or 'unknown'} build {os_info.get('build') or 'unknown'} "
            f"{os_info.get('architecture') or ''} (identification confidence {os_info.get('confidence', 'low')}). "
            f"{s.get('total_processes', 0)} processes ({s.get('terminated_processes', 0)} terminated, "
            f"{s.get('hidden_candidates', 0)} hidden candidates), {s.get('suspicious_processes', 0)} with risk >= 30; "
            f"{s.get('network_connections', 0)} network endpoints ({s.get('suspicious_connections', 0)} flagged); "
            f"{s.get('injected_memory_indicators', 0)} malfind regions; {s.get('findings', 0)} findings "
            f"({s.get('high_severity_findings', 0)} high/critical); {s.get('iocs', 0)} IOCs. "
            f"Overall risk {s.get('overall_risk_score', 0)} ({s.get('overall_risk_band', 'low')}). "
            f"Plugin failures: {', '.join(s.get('plugin_failures', {}) or []) or 'none'}. "
            f"Rules not evaluated: {', '.join(s.get('rules_not_evaluated', {}) or []) or 'none'}.")
        add(EvidenceDoc("SUMMARY", "summary", "Analysis summary", summary_text, None, "info", 0.0,
                        {**s, "os_info": os_info, "image": image.original_filename, "sha256": image.sha256,
                         "is_demo": image.is_demo}))

        blob = " ".join(d.text for d in docs.values()).lower()
        return EvidenceCorpus(job, docs, dict(by_pid), {p.pid for p in procs},
                              {p.name.lower() for p in procs}, blob)
