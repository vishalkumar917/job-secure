"""Memory-injection rules based on malfind, vadinfo and ldrmodules evidence.

malfind reports VADs that are private (not file-backed), executable and
committed. Such regions are produced by code injection and reflective loading,
but also by JIT compilers (.NET, JavaScript engines) and security products, so
confidence is reduced for processes on the JIT/security list.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.services.analysis.process_model import ProcessView
from app.services.detection.base import AnalysisContext, DetectionRule, Evidence, FindingDraft, register
from app.services.volatility.parsers import RegionRecord

RWX = {"PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY"}
MAX_EVIDENCE = 8

# Byte prologues commonly seen at the start of position-independent shellcode.
SHELLCODE_PROLOGUES: list[tuple[bytes, str]] = [
    (b"\xfc\x48\x83\xe4\xf0", "cld; and rsp,0xfffffffffffffff0 (x64 stack-alignment prologue)"),
    (b"\xfc\xe8", "cld; call (common x86 shellcode prologue)"),
    (b"\xe8\x00\x00\x00\x00", "call $+5 (GetPC technique)"),
    (b"\xd9\xee\xd9\x74\x24\xf4", "fldz; fnstenv [esp-0xc] (FPU GetPC technique)"),
    (b"\x60\xe8", "pushad; call (x86 shellcode prologue)"),
]

_NOT_PROVE_JIT = ("Executable private memory is also created by JIT compilers (.NET CLR, browsers, Java), "
                  "security products and some packers; this is an indicator, not proof of injection.")


def _is_exec(r: RegionRecord) -> bool:
    return bool(r.protection and "EXECUTE" in r.protection.upper())


def _is_private(r: RegionRecord) -> bool:
    if r.private_memory is not None:
        return r.private_memory
    return (r.tag or "").lower() == "vads"


def _is_zero(r: RegionRecord) -> bool:
    return bool(r.first_bytes) and not any(r.first_bytes)


def _region_ev(r: RegionRecord, desc: str, source: str = "windows.malfind") -> Evidence:
    return Evidence(source, "memory_region", desc,
                    f"{r.start}-{r.end} {r.protection or '?'} tag={r.tag or '?'} private={r.private_memory}",
                    ref=f"MEM:{r.pid}:{r.start}")


def _jit_factor(ctx: AnalysisContext, proc: ProcessView | None) -> tuple[float, str]:
    if proc and proc.name_lc in ctx.kb.jit_processes:
        return 0.5, f" {proc.name} is a known JIT/security process, so confidence is reduced."
    return 1.0, ""


class _MalfindRule(DetectionRule):
    required_plugins = ("windows.malfind",)

    def _per_process(self, ctx: AnalysisContext):
        for pid, regions in ctx.malfind_by_pid.items():
            yield pid, ctx.live_process(pid), regions


@register
class ExecutablePrivateMemoryRule(_MalfindRule):
    rule_id = "RULE_EXECUTABLE_PRIVATE_MEMORY"
    title = "Executable private memory (possible code injection)"
    category = "memory"
    severity = "high"
    points = 20
    attack = ["T1055"]
    description = "Committed, private (non file-backed) memory with execute permission reported by malfind."
    explanation = {
        "what": "The process contains executable memory that does not belong to any program or DLL file on disk.",
        "why": "Normally executable code is mapped from .exe/.dll files. Code living in anonymous private memory is how injected shellcode and reflectively loaded payloads typically appear.",
        "interpretation": "Possible process injection (e.g. VirtualAllocEx/WriteProcessMemory) or in-memory payload execution.",
        "not_prove": _NOT_PROVE_JIT,
        "next_steps": "Review the region's hexdump/disassembly, check for PE headers, compare with windows.vadinfo, and (in an isolated lab) dump the region for static analysis.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        for pid, proc, regions in self._per_process(ctx):
            hits = [r for r in regions if _is_exec(r) and _is_private(r)]
            if not hits:
                continue
            factor, note = _jit_factor(ctx, proc)
            zero_only = all(_is_zero(r) for r in hits)
            conf = (0.4 if zero_only else 0.65) * factor
            if zero_only:
                note += " The regions' leading bytes are zero (possibly paged or uninitialised), lowering confidence."
            name = proc.name if proc else (hits[0].process or f"PID {pid}")
            severity = "low" if factor < 1 else "medium" if zero_only else self.severity
            yield self.make(proc, f"{name} (PID {pid}) has {len(hits)} executable private memory region(s) "
                                  f"flagged by malfind.{note}",
                            [_region_ev(r, "Executable private region") for r in hits[:MAX_EVIDENCE]], conf,
                            "Inspect the hexdump/disassembly of each region and correlate with network and "
                            "command-line evidence for this process.", severity=severity)


@register
class RwxMemoryRule(_MalfindRule):
    rule_id = "RULE_RWX_MEMORY"
    title = "Read-write-execute (RWX) memory region"
    category = "memory"
    severity = "medium"
    points = 10
    attack = ["T1055"]
    description = "Memory that is simultaneously writable and executable (PAGE_EXECUTE_READWRITE)."
    explanation = {
        "what": "A memory region can be both written to and executed.",
        "why": "Injectors commonly allocate PAGE_EXECUTE_READWRITE memory, write a payload into it and run it. Well-behaved code rarely needs RWX memory.",
        "interpretation": "Possible staging area for injected or self-modifying code.",
        "not_prove": _NOT_PROVE_JIT,
        "next_steps": "Correlate with malfind hexdump content and the process's other indicators before drawing conclusions.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        for pid, proc, regions in self._per_process(ctx):
            hits = [r for r in regions if (r.protection or "").upper() in RWX]
            if not hits:
                continue
            factor, note = _jit_factor(ctx, proc)
            name = proc.name if proc else (hits[0].process or f"PID {pid}")
            yield self.make(proc, f"{name} (PID {pid}) has {len(hits)} RWX region(s).{note}",
                            [_region_ev(r, "RWX region") for r in hits[:MAX_EVIDENCE]], 0.55 * factor,
                            "Review region contents; RWX is significant when combined with other indicators.",
                            severity="low" if factor < 1 else self.severity)


@register
class PeInPrivateMemoryRule(_MalfindRule):
    rule_id = "RULE_PE_IN_PRIVATE_MEMORY"
    title = "PE image header in private executable memory (reflective loading indicator)"
    category = "memory"
    severity = "high"
    points = 25
    attack = ["T1055.001", "T1620"]
    description = "A malfind region begins with an 'MZ' DOS header, i.e. a PE file loaded outside the Windows loader."
    explanation = {
        "what": "A complete program image (it starts with the 'MZ' signature of Windows executables) sits in memory that was not loaded from a file.",
        "why": "The Windows loader maps DLLs/EXEs as image-backed memory. A PE header in private memory indicates a module that was copied in manually - typical of reflective DLL injection and in-memory loaders.",
        "interpretation": "Likely reflective loading or manual mapping of a PE payload.",
        "not_prove": "Some legitimate software (packers, DRM, certain security tools) manually maps images; the PE must be examined to determine what it is.",
        "next_steps": "In an isolated lab, dump the region and analyse the PE statically (imports, strings, signature); check YARA results for the region.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        for pid, proc, regions in self._per_process(ctx):
            hits = [r for r in regions if r.has_pe_header and _is_exec(r)]
            if not hits:
                continue
            name = proc.name if proc else (hits[0].process or f"PID {pid}")
            ev = [_region_ev(r, "Region starting with MZ header") for r in hits[:MAX_EVIDENCE]]
            ev += [Evidence("windows.malfind", "hexdump", "Leading bytes", r.first_bytes[:16].hex(" "),
                            ref=f"MEM:{r.pid}:{r.start}") for r in hits[:3]]
            yield self.make(proc, f"{name} (PID {pid}) has {len(hits)} private executable region(s) that begin with "
                                  f"a PE ('MZ') header - an indicator of reflective/manual PE loading.", ev, 0.8,
                            "Dump and statically analyse the embedded PE in an isolated environment.")


@register
class ShellcodeIndicatorRule(_MalfindRule):
    rule_id = "RULE_SHELLCODE_INDICATOR"
    title = "Shellcode-like instruction prologue in injected region"
    category = "memory"
    severity = "medium"
    points = 10
    attack = ["T1055"]
    description = "Leading bytes of a malfind region match well-known position-independent shellcode prologues."
    explanation = {
        "what": "The first instructions in a suspicious memory region look like the start of shellcode.",
        "why": "Position-independent shellcode commonly starts with characteristic sequences (stack alignment, GetPC tricks).",
        "interpretation": "The region may contain injected shellcode such as a stager.",
        "not_prove": "Short byte patterns can occur by coincidence in legitimate code; this is a weak-to-moderate indicator.",
        "next_steps": "Review the full disassembly of the region and look for API hashing, network or loader behaviour.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        for pid, proc, regions in self._per_process(ctx):
            ev: list[Evidence] = []
            for r in regions:
                if r.has_pe_header or not _is_exec(r):
                    continue
                for sig, label in SHELLCODE_PROLOGUES:
                    if r.first_bytes.startswith(sig):
                        ev.append(_region_ev(r, f"Prologue: {label}"))
                        ev.append(Evidence("windows.malfind", "hexdump", "Leading bytes",
                                           r.first_bytes[:16].hex(" "), ref=f"MEM:{r.pid}:{r.start}"))
                        break
            if ev:
                name = proc.name if proc else f"PID {pid}"
                yield self.make(proc, f"{name} (PID {pid}) has injected region(s) whose first bytes match known "
                                      f"shellcode prologues.", ev[:MAX_EVIDENCE], 0.55,
                                "Review the disassembly of the region for further shellcode characteristics.")


@register
class UnbackedExecutableVadRule(DetectionRule):
    rule_id = "RULE_UNBACKED_EXECUTABLE_VAD"
    title = "Executable VAD not backed by a file (vadinfo)"
    category = "memory"
    severity = "low"
    points = 5
    attack = ["T1055"]
    required_plugins = ("windows.vadinfo",)
    description = ("Targeted vadinfo shows private executable VADs with no mapped file in a triaged process. "
                   "VAD protection is the initial protection, so this complements malfind.")
    explanation = {
        "what": "The VAD tree of a triaged process contains executable regions with no file behind them.",
        "why": "This corroborates (or extends) malfind results using the full VAD tree.",
        "interpretation": "Additional dynamically created executable memory in the process.",
        "not_prove": "VAD protection reflects the protection at allocation time; JIT engines create such regions routinely.",
        "next_steps": "Cross-reference these regions with malfind output and YARA scan results.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        for pid, vads in ctx.vads_by_pid.items():
            malfind_starts = {r.start for r in ctx.malfind_by_pid.get(pid, [])}
            hits = [v for v in vads if _is_exec(v) and v.private_memory and not v.mapped_file
                    and v.start not in malfind_starts]
            if not hits:
                continue
            proc = ctx.live_process(pid)
            factor, note = _jit_factor(ctx, proc)
            name = proc.name if proc else f"PID {pid}"
            yield self.make(proc, f"vadinfo shows {len(hits)} additional private executable VAD(s) without a backing "
                                  f"file in {name} (PID {pid}).{note}",
                            [_region_ev(v, "Unbacked executable VAD", "windows.vadinfo") for v in hits[:MAX_EVIDENCE]],
                            0.4 * factor, "Compare with malfind results and examine the region contents.")


@register
class UnlinkedModuleRule(DetectionRule):
    rule_id = "RULE_UNLINKED_MODULE"
    title = "Mapped DLL missing from all PEB loader lists"
    category = "modules"
    severity = "high"
    points = 20
    attack = ["T1055.001", "T1564"]
    required_plugins = ("windows.ldrmodules",)
    description = "ldrmodules shows an image-mapped DLL absent from InLoad, InInit and InMem lists (unlinked)."
    explanation = {
        "what": "A DLL is mapped into the process, but the process's own module lists do not mention it.",
        "why": "Malware unlinks injected DLLs from the PEB loader lists so tools that enumerate modules (Task Manager, dlllist) do not show them.",
        "interpretation": "Possible hidden DLL injection.",
        "not_prove": "Images mapped for non-execution purposes and some protected processes can produce benign mismatches.",
        "next_steps": "Examine the mapped file path and region contents; check the DLL on disk if available.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        for pid, rows in ctx.ldr_by_pid.items():
            hits = [r for r in rows if (r.mapped_path or "").lower().endswith(".dll")
                    and r.in_load is False and r.in_init is False and r.in_mem is False]
            if not hits:
                continue
            proc = ctx.live_process(pid)
            for r in hits:
                ctx.flagged_modules[(pid, (r.mapped_path or "").lower())].append("unlinked from PEB loader lists")
            ev = [Evidence("windows.ldrmodules", "module", "Unlinked mapped image",
                           f"{r.mapped_path} base={r.base} InLoad=False InInit=False InMem=False")
                  for r in hits[:MAX_EVIDENCE]]
            name = proc.name if proc else f"PID {pid}"
            yield self.make(proc, f"{len(hits)} mapped DLL(s) in {name} (PID {pid}) are absent from all three PEB "
                                  f"loader lists.", ev, 0.65,
                            "Investigate each unlinked DLL path and its memory region.")


@register
class SuspiciousDllPathRule(DetectionRule):
    rule_id = "RULE_SUSPICIOUS_DLL_PATH"
    title = "DLL loaded from a user-writable or staging directory"
    category = "modules"
    severity = "medium"
    points = 15
    attack = ["T1574.002", "T1129"]
    required_plugins = ("windows.dlllist",)
    description = ("Flags modules loaded from Temp, Public, ProgramData and similar paths, and core Windows DLL "
                   "names loaded from outside system directories (DLL side-loading).")
    explanation = {
        "what": "The process loaded a DLL from a folder that ordinary users can write to, or a system-named DLL from an unexpected folder.",
        "why": "DLL side-loading and search-order hijacking place a malicious DLL where a program will load it; user-writable folders are the usual staging area.",
        "interpretation": "Possible DLL side-loading or a dropped malicious module.",
        "not_prove": "Some legitimate applications (especially per-user installs) load DLLs from AppData.",
        "next_steps": "Hash the DLL, check its signature and determine when and by which process it was written.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        from app.services.analysis.process_model import normalize_path

        kb = ctx.kb
        for pid, mods in ctx.modules_by_pid.items():
            proc = ctx.live_process(pid)
            main = proc.norm_path if proc else None
            ev: list[Evidence] = []
            sev, pts, conf = "medium", 15, 0.6
            for m in mods:
                npath = normalize_path(m.path)
                if not npath or npath == main:
                    continue
                if m.name.lower() in kb.system_dlls and not any(npath.startswith(d) for d in kb.system_dll_dirs):
                    reason = f"system DLL name {m.name} loaded outside system directories"
                    ctx.flagged_modules[(pid, (m.path or "").lower())].append(reason)
                    ev.append(Evidence("windows.dlllist", "module", "System DLL from unexpected path", m.path or "",
                                       ref=f"MOD:{pid}:{m.base}"))
                    sev, pts, conf = "high", 20, 0.75
                    continue
                hit = next((p for p in kb.path_patterns if p.regex.search(npath)), None)
                if hit:
                    ctx.flagged_modules[(pid, (m.path or "").lower())].append(f"loaded from {hit.label}")
                    ev.append(Evidence("windows.dlllist", "module", f"DLL in {hit.label}", m.path or "",
                                       ref=f"MOD:{pid}:{m.base}"))
            if ev:
                name = proc.name if proc else f"PID {pid}"
                yield self.make(proc, f"{name} (PID {pid}) loaded {len(ev)} module(s) from unusual locations.",
                                ev[:MAX_EVIDENCE], conf,
                                "Verify each DLL's signature and provenance; check for side-loading next to a "
                                "legitimate signed executable.", severity=sev, points=pts)
