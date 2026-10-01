"""Process-integrity rules: hiding, parent/child anomalies, paths, masquerading, duplicates."""

from __future__ import annotations

from collections.abc import Iterable

from app.services.detection.base import (
    AnalysisContext,
    DetectionRule,
    Evidence,
    FindingDraft,
    max_severity,
    proc_evidence,
    register,
)

_STD_NOT_PROVE = ("A single indicator does not prove malware. Legitimate software, administrative tooling and "
                  "acquisition artefacts can produce similar evidence.")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


@register
class ProcessHidingRule(DetectionRule):
    rule_id = "RULE_PROCESS_HIDING"
    title = "Process present in psscan but absent from pslist"
    category = "process_integrity"
    severity = "high"
    points = 20
    attack = ["T1014", "T1564"]
    required_plugins = ("windows.pslist", "windows.psscan")
    description = ("Cross-view analysis: an EPROCESS structure found by pool scanning (psscan) that is not linked "
                   "in the active process list (pslist) and has no exit time may have been unlinked (DKOM).")
    explanation = {
        "what": "A process object was found by scanning raw memory, but the operating system's own list of running processes does not contain it.",
        "why": "Rootkits hide processes by unlinking them from the ActiveProcessLinks list (Direct Kernel Object Manipulation). A live process visible only to a memory scan is the classic symptom.",
        "interpretation": "Possible process hiding by a rootkit, or a process that was being created/terminated while memory was acquired.",
        "not_prove": "It does not prove hiding: memory smear during live acquisition, or a process exiting mid-capture, can produce the same discrepancy.",
        "next_steps": "Check thread objects for the PID (windows.thrdscan), compare with csrss handle tables, and inspect the process with windows.vadinfo and windows.dlllist.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        for p in ctx.processes:
            if not p.is_hidden_candidate:
                continue
            ev = [
                Evidence("windows.psscan", "process", "Found by pool scanning", f"{p.name} PID {p.pid} offset {p.offset}",
                         ref=f"PROC:{p.pid}"),
                Evidence("windows.pslist", "process", "Absent from the active process list", f"PID {p.pid} not listed"),
                Evidence("windows.psscan", "process", "Exit time", "none recorded (process appears live)"),
            ]
            yield self.make(p, f"{p.label()} was found by psscan but is not linked in the active process list "
                               f"and has no exit time - a possible unlinked (hidden) process.", ev, 0.6,
                            "Corroborate with windows.thrdscan and windows.vadinfo for this PID; review whether the "
                            "image was acquired live (smear) before concluding the process was hidden.")


@register
class DuplicateSystemProcessRule(DetectionRule):
    rule_id = "RULE_DUPLICATE_SYSTEM_PROCESS"
    title = "Multiple instances of a singleton system process"
    category = "process_integrity"
    severity = "medium"
    points = 15
    attack = ["T1036.005"]
    description = "Processes such as lsass.exe, services.exe and wininit.exe normally run exactly once."
    explanation = {
        "what": "More than one copy of a Windows process that normally runs only once was found.",
        "why": "Attackers name malware after critical system processes so it blends in; a second lsass.exe or services.exe is a common masquerading tell.",
        "interpretation": "One of the instances may be an impostor using a trusted process name.",
        "not_prove": "Some system configurations (e.g. Credential Guard, crash/restart during capture) legitimately create extra instances.",
        "next_steps": "Compare the image paths, parents, creation times and loaded modules of each instance; the impostor usually differs on path or parent.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        live = [p for p in ctx.processes if not p.is_terminated]
        for name, base in ctx.kb.system_processes.items():
            if not base.singleton or name == "system":
                continue
            instances = [p for p in live if p.name_lc == name]
            if len(instances) < 2:
                continue
            ev = [proc_evidence(p) for p in instances]
            for p in instances:
                yield self.make(p, f"{len(instances)} live instances of {name} were found (expected 1). "
                                   f"PIDs: {', '.join(str(i.pid) for i in instances)}.", ev, 0.6,
                                "Compare path, parent and creation time of each instance to identify the outlier.")


@register
class SuspiciousParentRule(DetectionRule):
    rule_id = "RULE_SUSPICIOUS_PARENT"
    title = "Suspicious parent-child process relationship"
    category = "parent_child"
    severity = "high"
    points = 15
    attack = ["T1036", "T1204.002", "T1059"]
    required_plugins = ("windows.pslist",)
    description = ("Compares each process's parent with the expected Windows process hierarchy and flags "
                   "document/server applications spawning shells or script hosts.")
    explanation = {
        "what": "A process was started by a parent that does not normally start it.",
        "why": "Windows system processes have a fixed, well-documented ancestry (e.g. svchost.exe is started by services.exe). Office documents launching PowerShell or cmd is a hallmark of macro-based initial access.",
        "interpretation": "Possible malicious document execution, process masquerading or injection-based process spawning.",
        "not_prove": "Some legitimate add-ins, installers and management agents spawn shells; PPID can also be spoofed, so the 'real' creator may differ.",
        "next_steps": "Review the parent's command line and open documents (windows.handles, windows.filescan), and examine the child's command line and network activity.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        kb = ctx.kb
        for p in ctx.processes:
            parent = ctx.parent_of(p)
            reasons: list[tuple[str, str, int, float]] = []  # text, severity, points, confidence
            base = kb.system_processes.get(p.name_lc)
            if base and base.parents:
                if parent and parent.name_lc not in base.parents:
                    reasons.append((f"{p.name} is expected to be started by {' or '.join(base.parents)}, but its "
                                    f"parent is {parent.label()}.", "high", 15, 0.75))
                elif parent is None and not base.allow_orphan and p.ppid not in (None, 0):
                    reasons.append((f"Parent PID {p.ppid} of {p.name} is not present in memory; {p.name} is "
                                    f"normally started by {' or '.join(base.parents)} which stays running.",
                                    "low", 5, 0.35))
            if parent and parent.name_lc in kb.document_apps and p.name_lc in kb.shells:
                reasons.append((f"Document/server application {parent.label()} spawned {p.name}, a shell or "
                                f"script host.", "high", 15, 0.8))
            if parent and parent.name_lc in kb.sensitive_parents and p.name_lc in kb.shells:
                reasons.append((f"Sensitive system process {parent.label()} spawned {p.name}.", "high", 15, 0.8))
            if not reasons:
                continue
            ev = [proc_evidence(p, "windows.pstree")]
            if parent:
                ev.append(Evidence("windows.pstree", "process", "Parent process",
                                   f"{parent.name} PID {parent.pid}", ref=f"PROC:{parent.pid}"))
            else:
                ev.append(Evidence("windows.pstree", "process", "Parent process", f"PID {p.ppid} not found"))
            text = " ".join(r[0] for r in reasons)
            yield self.make(p, text, ev, max(r[3] for r in reasons),
                            "Review the parent's command line and documents it had open; check the child's "
                            "command line, modules and network connections.",
                            severity=max_severity(*(r[1] for r in reasons)), points=max(r[2] for r in reasons))


@register
class SuspiciousPathRule(DetectionRule):
    rule_id = "RULE_SUSPICIOUS_PATH"
    title = "Process executing from a user-writable or staging directory"
    category = "path"
    severity = "medium"
    points = 20
    attack = ["T1036", "T1204"]
    description = "Flags process images located in temporary, public, recycle-bin or similar world-writable paths."
    explanation = {
        "what": "The program's executable file is located in a folder that ordinary users can write to.",
        "why": "Malware droppers commonly stage payloads in Temp, Public, ProgramData or the Recycle Bin because no administrative rights are needed to write there.",
        "interpretation": "The process may have been dropped by another program or downloaded rather than installed.",
        "not_prove": "Many legitimate installers, updaters and portable tools also run from these folders.",
        "next_steps": "Hash and examine the file on disk (if available), check its digital signature, and review which process created it.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        for p in ctx.processes:
            npath = p.norm_path
            if not npath:
                continue
            hits = [pat for pat in ctx.kb.path_patterns if pat.regex.search(npath)]
            if not hits:
                continue
            top = max(hits, key=lambda h: h.points)
            ev = [Evidence(_path_source(p), "process", "Image path", p.path or "", ref=f"PROC:{p.pid}"),
                  Evidence("knowledge-base", "rule", "Matched location", top.label)]
            yield self.make(p, f"{p.label()} is running from {top.label}: {p.path}.", ev,
                            0.55 if top.severity == "low" else 0.65,
                            "Verify the file's signature and origin; determine which process wrote it to disk.",
                            severity=top.severity, points=top.points)


@register
class MasqueradingRule(DetectionRule):
    rule_id = "RULE_MASQUERADING"
    title = "Process masquerading as a Windows system binary"
    category = "masquerading"
    severity = "high"
    points = 25
    attack = ["T1036.005"]
    description = ("A process uses the name of a Windows system binary but runs from a non-standard path, or uses "
                   "a near-identical (typo-squatted) name.")
    explanation = {
        "what": "A process is named like a trusted Windows component but is not where that component lives, or its name is a near copy of one.",
        "why": "Masquerading - a copy of svchost.exe in a user folder, or a name differing by one or two characters - is used to evade casual inspection by analysts and users.",
        "interpretation": "A strong indicator that the binary is not the genuine Windows component.",
        "not_prove": "Some third-party software legitimately ships files with system-like names; the binary itself must be examined.",
        "next_steps": "Acquire the binary from disk (or dump it from memory in a lab), compare its hash against known-good versions and check its signature.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        kb = ctx.kb
        sys_names = [n for n in kb.system_processes if n.endswith(".exe")]
        for p in ctx.processes:
            name = p.name_lc
            base = kb.system_processes.get(name)
            if base and base.paths and p.norm_path:
                if not any(p.norm_path.endswith(exp) for exp in base.paths):
                    ev = [Evidence(_path_source(p), "process", "Observed path", p.path or "", ref=f"PROC:{p.pid}"),
                          Evidence("knowledge-base", "baseline", "Expected path", " or ".join(base.paths))]
                    yield self.make(p, f"{p.label()} runs from {p.path}; the genuine {name} lives in "
                                       f"{' or '.join(base.paths)}.", ev, 0.85,
                                    "Treat as a probable impostor: examine its modules, memory regions and network "
                                    "activity, and recover the binary for static analysis.")
                continue
            if name in kb.lookalike_allowlist or not name.endswith(".exe") or len(name) < 8:
                continue
            stem = name[:-4]
            for target in sys_names:
                tstem = target[:-4]
                if len(p.name) >= 14 and tstem.startswith(stem):
                    continue  # EPROCESS.ImageFileName truncation, not a lookalike
                dist = _levenshtein(stem, tstem)
                if 0 < dist <= (1 if len(tstem) <= 5 else 2):
                    ev = [proc_evidence(p),
                          Evidence("knowledge-base", "baseline", "Similar system process name", target)]
                    yield self.make(p, f"Process name '{p.name}' is a near-copy of the system binary '{target}' "
                                       f"(edit distance {dist}).", ev, 0.7,
                                    "Inspect the binary path and signature; typo-squatted names are a common "
                                    "masquerading technique.", points=20)
                    break


def _path_source(p) -> str:
    src = (p.path_source or "").split(" ")[0]
    return {"pstree": "windows.pstree", "dlllist": "windows.dlllist", "cmdline": "windows.cmdline"}.get(src, "derived")
