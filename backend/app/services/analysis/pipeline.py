"""The staged forensic analysis pipeline.

    identification -> process enumeration -> execution context -> network ->
    injection -> triage (detection pass 1) -> targeted deep dive ->
    optional YARA/filescan -> final detection -> risk scoring -> IOC extraction ->
    timeline -> persistence -> grounded case summary

Every plugin execution is recorded in ``plugin_runs`` (args, timing, status,
error, SHA-256 of raw output). A failed plugin never aborts the pipeline; only
when *no* process listing can be obtained is the analysis marked failed.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import get_logger
from app.models import (
    IOC,
    AIAnalysis,
    AnalysisJob,
    ChatMessage,
    Finding,
    HandleRecord,
    MemoryRegion,
    Module,
    NetworkConnection,
    PluginRun,
    Process,
    ProcessRelationship,
    TimelineEvent,
    YaraMatch,
)
from app.services.analysis.process_model import ProcessView, build_process_views
from app.services.analysis.sources import EvidenceSource
from app.services.detection.base import AnalysisContext
from app.services.detection.engine import DetectionEngine, DetectionResult
from app.services.detection.knowledge import KnowledgeBase
from app.services.ioc.extractor import extract_iocs
from app.services.ioc.patterns import WIN_PATH, is_external
from app.services.scoring.risk import ScoringModel, score_processes
from app.services.timeline.builder import build_timeline
from app.services.volatility import parsers as vp
from app.services.volatility.identification import identify
from app.services.volatility.plugins import PLUGINS
from app.services.volatility.runner import PluginResult

log = get_logger(__name__)

PARSERS: dict[str, tuple[str, Callable[[list[dict[str, Any]]], Any]]] = {
    "windows.pslist": ("pslist", vp.parse_processes),
    "windows.psscan": ("psscan", vp.parse_processes),
    "windows.pstree": ("pstree", vp.parse_processes),
    "windows.cmdline": ("cmdlines", vp.parse_cmdline),
    "windows.dlllist": ("modules", vp.parse_dlllist),
    "windows.ldrmodules": ("ldrmodules", vp.parse_ldrmodules),
    "windows.malfind": ("malfind", vp.parse_regions),
    "windows.vadinfo": ("vads", vp.parse_regions),
    "windows.netscan": ("network", vp.parse_netscan),
    "windows.netstat": ("network", vp.parse_netscan),
    "windows.handles": ("handles", vp.parse_handles),
    "windows.getsids": ("sids", vp.parse_sids),
    "windows.privileges": ("privileges", vp.parse_privileges),
    "windows.vadyarascan": ("yara", vp.parse_yara),
}
DEEP_PLUGINS = ["windows.vadinfo", "windows.ldrmodules", "windows.handles", "windows.getsids", "windows.privileges"]


class AnalysisAborted(Exception):
    pass


class AnalysisPipeline:
    def __init__(self, db: Session, job: AnalysisJob, settings: Settings, source: EvidenceSource,
                 kb: KnowledgeBase, enabled_rules: set[str] | None, yara_bundle: Path | None = None):
        self.db = db
        self.job = job
        self.settings = settings
        self.source = source
        self.kb = kb
        self.enabled_rules = enabled_rules
        self.yara_bundle = yara_bundle
        self.ev = vp.ParsedEvidence()
        self.plugin_failures: dict[str, str] = {}
        self.filescan_paths: list[str] = []

    # ------------------------------------------------------------------ helpers
    def _progress(self, stage: str, pct: int) -> None:
        self.job.stage, self.job.progress = stage, pct
        self.db.commit()

    def _run(self, plugin: str, *, pids: list[int] | None = None, yara_file: Path | None = None) -> PluginResult:
        spec = PLUGINS[plugin]
        started = datetime.now(timezone.utc)
        log.info("plugin started", extra={"analysis_id": self.job.id, "plugin": plugin, "pids": pids})
        try:
            res = self.source.run(plugin, pids=pids, yara_file=yara_file)
        except Exception as exc:  # noqa: BLE001 - a plugin must never crash the pipeline
            res = PluginResult(plugin, "failed", error=f"{type(exc).__name__}: {exc}")
        ended = datetime.now(timezone.utc)
        if res.output_path and not res.output_sha256 and Path(res.output_path).is_file():
            res.output_sha256 = hashlib.sha256(Path(res.output_path).read_bytes()).hexdigest()
        self.db.add(PluginRun(job_id=self.job.id, plugin=plugin, stage=spec.stage, rationale=spec.rationale,
                              args=res.args, status=res.status, started_at=started, ended_at=ended,
                              duration_ms=res.duration_ms or int((ended - started).total_seconds() * 1000),
                              row_count=len(res.rows), error=res.error, output_path=res.output_path,
                              output_sha256=res.output_sha256))
        self.db.commit()
        log.info("plugin finished", extra={"analysis_id": self.job.id, "plugin": plugin, "status": res.status,
                                           "duration_ms": res.duration_ms, "rows": len(res.rows),
                                           "error": res.error})
        if res.ok:
            self.ev.available.add(plugin)
            if plugin in PARSERS:
                attr, parser = PARSERS[plugin]
                try:
                    getattr(self.ev, attr).extend(parser(res.rows))
                except Exception as exc:  # noqa: BLE001
                    log.exception("parser failed", extra={"analysis_id": self.job.id, "plugin": plugin})
                    self.plugin_failures[plugin] = f"output could not be parsed: {exc}"
                    self.ev.available.discard(plugin)
        else:
            self.plugin_failures[plugin] = res.error or res.status
        return res

    def _skip(self, plugin: str, reason: str) -> None:
        spec = PLUGINS[plugin]
        self.db.add(PluginRun(job_id=self.job.id, plugin=plugin, stage=spec.stage, rationale=spec.rationale,
                              status="skipped", error=reason, args=[]))
        self.db.commit()

    def _detect(self) -> tuple[list[ProcessView], AnalysisContext, DetectionResult]:
        views = build_process_views(self.ev)
        ctx = AnalysisContext(views, self.ev, self.kb)
        return views, ctx, DetectionEngine(self.enabled_rules).run(ctx)

    # ------------------------------------------------------------------ main flow
    def execute(self) -> None:
        self._progress("identification", 3)
        info_res = self._run("windows.info")
        if info_res.ok:
            self.ev.info = vp.parse_info(info_res.rows)
        image = self.job.image
        image.os_info = identify(self.ev.info, image.validation_notes)
        self.job.volatility_version = self.source.version()
        self.db.commit()

        self._progress("process_enumeration", 10)
        for plugin, pct in (("windows.pslist", 14), ("windows.psscan", 20), ("windows.pstree", 25)):
            self._run(plugin)
            self._progress("process_enumeration", pct)
        if not ({"windows.pslist", "windows.psscan", "windows.pstree"} & self.ev.available):
            reason = self.plugin_failures.get("windows.info") or self.plugin_failures.get("windows.pslist")
            raise AnalysisAborted(
                "No process listing could be extracted from this image, so it cannot be analysed. "
                + (reason or "The file may not be a Windows memory image, may be corrupted, or symbols are missing."))

        self._progress("execution_context", 30)
        self._run("windows.cmdline")
        self._progress("execution_context", 36)
        self._run("windows.dlllist")

        self._progress("network", 42)
        if not self._run("windows.netscan").ok:
            self._run("windows.netstat")

        self._progress("injection_detection", 50)
        self._run("windows.malfind")

        # ---- triage: first detection pass decides where to spend expensive plugins
        self._progress("triage", 56)
        views, ctx, det = self._detect()
        model = ScoringModel.from_config(self.kb.scoring)
        scores = score_processes(det.findings, model)
        ranked = sorted(((s[0], key) for key, s in scores.items() if s[0] > 0), reverse=True)
        by_key = {v.key: v for v in views}
        targets: list[int] = []
        for _, key in ranked:
            p = by_key.get(key)
            if p and not p.is_terminated and p.pid not in targets:
                targets.append(p.pid)
        for p in views:
            if p.is_hidden_candidate and p.pid not in targets:
                targets.append(p.pid)
        targets = targets[: self.settings.deep_scan_max_pids]

        self._progress("deep_dive", 60)
        if targets:
            for i, plugin in enumerate(DEEP_PLUGINS):
                self._run(plugin, pids=targets)
                self._progress("deep_dive", 60 + (i + 1) * 4)
        else:
            for plugin in DEEP_PLUGINS:
                self._skip(plugin, "No process met the triage threshold for targeted analysis.")

        self._progress("yara", 82)
        if self.yara_bundle:
            scan_pids = None if self.settings.yara_scan_all_processes else (targets or None)
            if scan_pids is None and not self.settings.yara_scan_all_processes:
                self._skip("windows.vadyarascan", "No triaged processes to scan.")
            else:
                self._run("windows.vadyarascan", pids=scan_pids, yara_file=self.yara_bundle)
        else:
            self._skip("windows.vadyarascan", "No enabled YARA rules.")

        if self.settings.enable_filescan:
            res = self._run("windows.filescan")
            if res.ok:
                for row in res.rows:
                    name = vp.get(row, "Name")
                    if isinstance(name, str):
                        self.filescan_paths.append(name)
        else:
            self._skip("windows.filescan", "Disabled (ENABLE_FILESCAN=false); slow on large images.")

        # ---- final detection, scoring, IOC, timeline
        self._progress("correlation", 88)
        views, ctx, det = self._detect()
        scores = score_processes(det.findings, model)
        iocs = extract_iocs(ctx, {k: v[0] for k, v in scores.items()})
        for path in self.filescan_paths:
            npath = path.lower()
            if any(p.regex.search(npath) for p in self.kb.path_patterns) and WIN_PATH.search("c:" + path):
                from app.services.ioc.extractor import IocDraft
                iocs.append(IocDraft("file_path", path, "windows.filescan", None, None, "low",
                                     "file object in user-writable location"))
        timeline = build_timeline(ctx, det.findings, {k: v[1] for k, v in scores.items()})

        self._progress("persisting", 94)
        self._persist(views, ctx, det, scores, iocs, timeline, model, targets)

    # ------------------------------------------------------------------ persistence
    def _persist(self, views, ctx: AnalysisContext, det: DetectionResult, scores, iocs, timeline,
                 model: ScoringModel, targets: list[int]) -> None:
        db, job_id = self.db, self.job.id
        for model_cls in (TimelineEvent, IOC, ChatMessage, AIAnalysis, Finding, YaraMatch, HandleRecord, MemoryRegion,
                          NetworkConnection, Module, ProcessRelationship, Process):
            db.execute(delete(model_cls).where(model_cls.job_id == job_id))
        db.flush()

        proc_rows: dict[str, Process] = {}
        for v in views:
            score, band, contributors = scores.get(v.key, (0, model.band(0), []))
            row = Process(job_id=job_id, pid=v.pid, ppid=v.ppid, name=v.name, path=v.path, cmdline=v.cmdline,
                          create_time=v.create_time, exit_time=v.exit_time, threads=v.threads,
                          handle_count=v.handles, session_id=v.session_id, wow64=v.wow64, offset=v.offset,
                          in_pslist=v.in_pslist, in_psscan=v.in_psscan, in_pstree=v.in_pstree,
                          is_hidden_candidate=v.is_hidden_candidate, is_terminated=v.is_terminated,
                          user_sids=v.sids, privileges=v.privileges,
                          deep_scanned=v.pid in targets and not v.is_terminated,
                          risk_score=score, risk_band=band, risk_contributors=contributors)
            db.add(row)
            proc_rows[v.key] = row
        db.flush()

        def pid_row(pid: int | None) -> Process | None:
            p = ctx.live_process(pid)
            return proc_rows.get(p.key) if p else None

        anomalous_children = {f.process_key for f in det.findings if f.rule_id == "RULE_SUSPICIOUS_PARENT"}
        for v in views:
            parent = ctx.parent_of(v)
            if parent:
                db.add(ProcessRelationship(job_id=job_id, parent_process_id=proc_rows[parent.key].id,
                                           child_process_id=proc_rows[v.key].id, parent_pid=parent.pid,
                                           child_pid=v.pid, is_anomalous=v.key in anomalous_children))

        ldr_index = {(r.pid, r.base): r for r in self.ev.ldrmodules}
        for m in self.ev.modules:
            reasons = ctx.flagged_modules.get((m.pid, (m.path or "").lower()), [])
            ldr = ldr_index.get((m.pid, m.base))
            prow = pid_row(m.pid)
            db.add(Module(job_id=job_id, process_id=prow.id if prow else None, pid=m.pid, name=m.name, path=m.path,
                          base=m.base, size=m.size, load_time=m.load_time,
                          in_load=ldr.in_load if ldr else None, in_init=ldr.in_init if ldr else None,
                          in_mem=ldr.in_mem if ldr else None, is_suspicious=bool(reasons), reason="; ".join(reasons)))
        known_bases = {(m.pid, m.base) for m in self.ev.modules}
        for r in self.ev.ldrmodules:  # unlinked modules do not appear in dlllist - store them too
            reasons = ctx.flagged_modules.get((r.pid, (r.mapped_path or "").lower()), [])
            if (r.pid, r.base) in known_bases or not reasons:
                continue
            prow = pid_row(r.pid)
            db.add(Module(job_id=job_id, process_id=prow.id if prow else None, pid=r.pid,
                          name=(r.mapped_path or "?").split("\\")[-1], path=r.mapped_path, base=r.base,
                          in_load=r.in_load, in_init=r.in_init, in_mem=r.in_mem, is_suspicious=True,
                          reason="; ".join(reasons)))

        for idx, c in enumerate(self.ev.network):
            reasons = ctx.flagged_connections.get(idx, [])
            prow = pid_row(c.pid)
            db.add(NetworkConnection(job_id=job_id, process_id=prow.id if prow else None, pid=c.pid, owner=c.owner,
                                     protocol=c.protocol, local_addr=c.local_addr, local_port=c.local_port,
                                     foreign_addr=c.foreign_addr, foreign_port=c.foreign_port, state=c.state,
                                     created=c.created, offset=c.offset, is_external=is_external(c.foreign_addr),
                                     is_suspicious=bool(reasons), reason="; ".join(dict.fromkeys(reasons))))

        for source, regions in (("malfind", self.ev.malfind), ("vadinfo", self.ev.vads)):
            for r in regions:
                if source == "vadinfo" and "EXECUTE" not in (r.protection or "").upper():
                    continue  # store executable VADs only; full vadinfo output is kept on disk
                prow = pid_row(r.pid)
                db.add(MemoryRegion(job_id=job_id, process_id=prow.id if prow else None, pid=r.pid,
                                    process_name=r.process, source=source, start=r.start, end=r.end,
                                    protection=r.protection, tag=r.tag, private_memory=r.private_memory,
                                    commit_charge=r.commit_charge, mapped_file=r.mapped_file,
                                    has_pe_header=r.has_pe_header, hexdump=r.hexdump, disasm=r.disasm, notes=r.notes))

        for h in self.ev.handles:
            prow = pid_row(h.pid)
            db.add(HandleRecord(job_id=job_id, process_id=prow.id if prow else None, pid=h.pid,
                                handle_value=h.handle_value, handle_type=h.handle_type,
                                granted_access=h.granted_access, name=h.name))

        for y in self.ev.yara:
            p = ctx.live_process(y.pid)
            db.add(YaraMatch(job_id=job_id, process_id=proc_rows[p.key].id if p else None, pid=y.pid,
                             process_name=p.name if p else None, rule_name=y.rule, offset=y.offset,
                             component=y.component, matched_value=y.value,
                             severity=self.kb.yara_severity.get(y.rule, "medium")))

        finding_rows: list[Finding] = []
        for f in det.findings:
            prow = proc_rows.get(f.process_key or "")
            row = Finding(job_id=job_id, process_id=prow.id if prow else None, rule_id=f.rule_id, title=f.title,
                          category=f.category, severity=f.severity, confidence=round(f.confidence, 2),
                          finding=f.finding, evidence=[e.to_dict() for e in f.evidence],
                          recommendation=f.recommendation, pid=f.pid, process_name=f.process_name,
                          points=f.points, attack_techniques=f.attack)
            db.add(row)
            finding_rows.append(row)

        for i in iocs:
            prow = proc_rows.get(i.process_key or "") or pid_row(i.pid)
            db.add(IOC(job_id=job_id, process_id=prow.id if prow else None, ioc_type=i.ioc_type, value=i.value,
                       source=i.source, pid=i.pid, process_name=i.process_name, confidence=i.confidence,
                       context=i.context, watchlist_match=i.watchlist_match))
        db.flush()

        for t in timeline:
            ref = t.evidence_ref
            if ref and ref.startswith("FINDING:"):
                ref = f"F-{finding_rows[int(ref.split(':')[1])].id}"
            db.add(TimelineEvent(job_id=job_id, timestamp=t.timestamp, timestamp_source=t.timestamp_source,
                                 pid=t.pid, process_name=t.process_name, event_type=t.event_type,
                                 description=t.description, evidence_ref=ref, severity=t.severity))

        self.job.summary = self._summary(views, ctx, det, scores, iocs, model)
        self.job.overall_risk_score = self.job.summary["overall_risk_score"]
        self.job.overall_risk_band = self.job.summary["overall_risk_band"]
        db.commit()

    def _summary(self, views: list[ProcessView], ctx: AnalysisContext, det: DetectionResult, scores, iocs,
                 model: ScoringModel) -> dict:
        sev = Counter(f.severity for f in det.findings)
        cats = Counter(f.category for f in det.findings)
        proc_scores = [scores.get(v.key, (0, "low", []))[0] for v in views]
        overall = max(proc_scores, default=0)
        suspicious_conns = len(ctx.flagged_connections)
        return {
            "total_processes": len(views),
            "live_processes": sum(1 for v in views if not v.is_terminated),
            "terminated_processes": sum(1 for v in views if v.is_terminated),
            "hidden_candidates": sum(1 for v in views if v.is_hidden_candidate),
            "suspicious_processes": sum(1 for s in proc_scores if s >= 30),
            "network_connections": len(self.ev.network),
            "external_connections": sum(1 for n in self.ev.network if is_external(n.foreign_addr)),
            "suspicious_connections": suspicious_conns,
            "injected_memory_indicators": len(self.ev.malfind),
            "modules": len(self.ev.modules),
            "iocs": len(iocs),
            "findings": len(det.findings),
            "high_severity_findings": sev.get("high", 0) + sev.get("critical", 0),
            "severity_counts": {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
            "category_counts": dict(cats),
            "risk_distribution": {b: sum(1 for s in proc_scores if model.band(s) == b and s > 0)
                                  for b, _, _ in model.bands},
            "overall_risk_score": overall,
            "overall_risk_band": model.band(overall),
            "plugins_available": sorted(self.ev.available),
            "plugin_failures": self.plugin_failures,
            "rules_not_evaluated": det.not_evaluated,
            "rule_errors": det.errors,
            "synthetic": bool(getattr(self.source, "synthetic", False)),
            "scoring_model": model.describe(),
        }
