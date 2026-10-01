"""Automated IOC extraction from structured forensic evidence.

Sources: command lines (URLs, domains, IPs, paths, registry keys, hashes),
network endpoints (external remote IPs), suspicious modules and processes,
handles of triaged processes (registry keys, mutants) and YARA matches.
Confidence reflects provenance: indicators tied to high-risk processes or
watchlist entries are "high", generic extractions "low".
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.analysis.process_model import ProcessView, normalize_path
from app.services.detection.cmdline import decode_powershell
from app.services.detection.base import AnalysisContext
from app.services.ioc import patterns as P


@dataclass
class IocDraft:
    ioc_type: str
    value: str
    source: str
    pid: int | None
    process_name: str | None
    confidence: str
    context: str
    process_key: str | None = None
    watchlist_match: bool = False


class IocCollector:
    def __init__(self, watchlist: dict[str, dict[str, str]]):
        self.items: dict[tuple[str, str, int | None], IocDraft] = {}
        self.watchlist = watchlist

    def add(self, ioc_type: str, value: str, source: str, proc: ProcessView | None, confidence: str,
            context: str, pid: int | None = None) -> None:
        value = value.strip().rstrip(".,;)'\"")
        if not value:
            return
        pid = proc.pid if proc else pid
        key = (ioc_type, value.lower(), pid)
        wl_type = {"ipv4": "ipv4", "domain": "domain", "sha256": "sha256", "process_name": "file_name"}.get(ioc_type)
        on_watchlist = bool(wl_type and value.lower() in self.watchlist.get(wl_type, {}))
        if on_watchlist:
            confidence = "high"
        existing = self.items.get(key)
        rank = {"low": 0, "medium": 1, "high": 2}
        if existing is None or rank[confidence] > rank[existing.confidence]:
            self.items[key] = IocDraft(ioc_type, value, source, pid, proc.name if proc else None, confidence,
                                       context[:500], proc.key if proc else None, on_watchlist)


_SYSTEM_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\program files\\",
                "\\program files (x86)\\")


def _system_location(path: str) -> bool:
    """Standard OS/program locations - not useful as indicators on their own."""
    n = normalize_path(path) or ""
    return n.startswith(_SYSTEM_DIRS) or n == "\\windows\\explorer.exe"


def _level(risk: int, high: int = 60, medium: int = 30) -> str:
    return "high" if risk >= high else "medium" if risk >= medium else "low"


def extract_iocs(ctx: AnalysisContext, process_scores: dict[str, int]) -> list[IocDraft]:
    col = IocCollector(ctx.kb.watchlist)

    def risk(p: ProcessView | None) -> int:
        return process_scores.get(p.key, 0) if p else 0

    # 1. Command lines (and decoded -EncodedCommand payloads)
    for p in ctx.processes:
        if not p.cmdline:
            continue
        r = risk(p)
        conf = _level(r)
        decoded = decode_powershell(p.cmdline)
        sources = [(p.cmdline, f"command line of {p.label()}")]
        if decoded:
            sources.append((decoded, f"decoded -EncodedCommand payload of {p.label()}"))
        for text, ctx_txt in sources:
            for m in P.URL.finditer(text):
                col.add("url", m.group(0), "windows.cmdline", p, "high" if r >= 30 else "medium", ctx_txt)
            for m in P.DOMAIN.finditer(text):
                d = m.group(1)
                if P.is_valid_domain(d):
                    col.add("domain", d.lower(), "windows.cmdline", p, conf if r >= 30 else "low", ctx_txt)
            for m in P.IPV4.finditer(text):
                if P.classify_ip(m.group(0)) in {"public", "documentation"}:
                    col.add("ipv4", m.group(0), "windows.cmdline", p, conf, ctx_txt)
            for m in P.REGISTRY.finditer(text):
                col.add("registry_key", m.group(0), "windows.cmdline", p, conf, ctx_txt)
            for rx, t in ((P.SHA256, "sha256"), (P.SHA1, "sha1"), (P.MD5, "md5")):
                for m in rx.finditer(text):
                    col.add(t, m.group(0).lower(), "windows.cmdline", p, conf, ctx_txt)
            if r >= 30:
                for m in P.WIN_PATH.finditer(text):
                    if not _system_location(m.group(0)):
                        col.add("file_path", m.group(0), "windows.cmdline", p, conf, ctx_txt)
        if r >= 30:
            col.add("command", p.cmdline[:500], "windows.cmdline", p, conf, f"full command line of {p.label()}")
            if decoded:
                col.add("command", decoded[:500], "derived (decoded PowerShell)", p, conf,
                        f"decoded -EncodedCommand payload of {p.label()}")

    # 2. Network endpoints
    for idx, c in enumerate(ctx.evidence.network):
        if not P.is_external(c.foreign_addr):
            continue
        proc = ctx.live_process(c.pid)
        flagged = idx in ctx.flagged_connections
        conf = "high" if flagged and risk(proc) >= 30 else "medium" if flagged or risk(proc) >= 30 else "low"
        col.add("ipv4" if ":" not in (c.foreign_addr or "") else "ipv6", c.foreign_addr or "", "windows.netscan",
                proc, conf, f"{c.protocol} {c.state or ''} remote port {c.foreign_port}", pid=c.pid)

    # 3. Suspicious processes (name + image path)
    for p in ctx.processes:
        r = risk(p)
        if r < 30:
            continue
        col.add("process_name", p.name, "windows.pslist", p, _level(r), f"risk score {r}")
        if p.path and not _system_location(p.path):
            col.add("file_path", p.path, p.path_source or "derived", p, _level(r), "process image path")

    # 4. Modules flagged by rules
    for (pid, path_lc), reasons in ctx.flagged_modules.items():
        proc = ctx.live_process(pid)
        mod = next((m for m in ctx.modules_by_pid.get(pid, []) if (m.path or "").lower() == path_lc), None)
        ldr = next((x for x in ctx.ldr_by_pid.get(pid, []) if (x.mapped_path or "").lower() == path_lc), None)
        path = (mod.path if mod else None) or (ldr.mapped_path if ldr else None) or path_lc
        name = mod.name if mod else path.split("\\")[-1]
        source = "windows.dlllist" if mod else "windows.ldrmodules"
        col.add("dll", name, source, proc, "high" if risk(proc) >= 60 else "medium", "; ".join(reasons))
        col.add("file_path", path, source, proc, "medium", "suspicious module path")

    # 5. Handles of triaged processes: registry keys and mutants
    for pid, handles in ctx.handles_by_pid.items():
        proc = ctx.live_process(pid)
        if risk(proc) < 30:
            continue
        for h in handles:
            t = (h.handle_type or "").lower()
            if t == "key" and h.name and "\\currentversion\\run" in h.name.lower():
                col.add("registry_key", h.name, "windows.handles", proc, "medium", "open handle to autorun key")
            elif t == "mutant" and h.name:
                col.add("mutex", h.name, "windows.handles", proc, "medium", "named mutex held by suspicious process")

    # 6. YARA
    for m in ctx.evidence.yara:
        proc = ctx.live_process(m.pid)
        col.add("yara_rule", m.rule, "windows.vadyarascan", proc, "medium", f"match at {m.offset}", pid=m.pid)

    return sorted(col.items.values(), key=lambda i: ({"high": 0, "medium": 1, "low": 2}[i.confidence], i.ioc_type))
