"""Catalogue of Volatility 3 plugins used by the pipeline and *why* each one is run.

The pipeline is staged rather than "run everything":

1. Identification     - windows.info confirms the image contains a Windows kernel and
                        that matching symbols resolve. Every later plugin depends on it.
2. Process enumeration- pslist (walks the active-process linked list), psscan (pool-tag
                        scanning that also finds unlinked/terminated EPROCESS blocks) and
                        pstree (parent/child structure). Comparing pslist vs psscan is the
                        classic cross-view technique for detecting DKOM process hiding.
3. Execution context  - cmdline (process arguments) and dlllist (loaded modules, and the
                        main image path).
4. Network            - netscan (pool-scanned TCP/UDP endpoints with owning PID).
5. Injection          - malfind (private, executable VADs not backed by a file).
6. Triage             - the detection engine runs on the evidence above and selects the
                        most suspicious PIDs (bounded by DEEP_SCAN_MAX_PIDS).
7. Targeted deep dive - vadinfo, ldrmodules, handles, getsids and privileges are expensive
                        and very noisy system-wide, so they run only for triaged PIDs.
8. Optional           - vadyarascan (when YARA rules are enabled) and filescan (opt-in, slow).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PluginSpec:
    name: str
    stage: str
    rationale: str
    targeted: bool = False  # True -> run with --pid for triaged processes only
    required: bool = False
    optional: bool = False
    # CLI names to try in order. Volatility 3 >= 2.2x moved some plugins under windows.malware.*
    # and keeps the old names as deprecated aliases; older releases only know the old names.
    cli_names: tuple[str, ...] = ()

    @property
    def candidates(self) -> tuple[str, ...]:
        return self.cli_names or (self.name,)


PLUGINS: dict[str, PluginSpec] = {
    p.name: p
    for p in [
        PluginSpec("windows.info", "identification", "Confirms a Windows kernel can be located, resolves "
                   "symbols and reports OS build/architecture. All other plugins depend on this succeeding.",
                   required=True),
        PluginSpec("windows.pslist", "process_enumeration", "Walks the kernel's active process list "
                   "(ActiveProcessLinks) - the view the OS itself presents."),
        PluginSpec("windows.psscan", "process_enumeration", "Scans physical memory for EPROCESS pool "
                   "allocations. Finds terminated processes and processes unlinked from the active list "
                   "(DKOM hiding). Cross-viewed against pslist."),
        PluginSpec("windows.pstree", "process_enumeration", "Reconstructs parent/child relationships and, "
                   "on newer Volatility versions, the image path and command line from the PEB."),
        PluginSpec("windows.cmdline", "execution_context", "Recovers process command lines from the PEB to "
                   "detect encoded PowerShell, LOLBin abuse and execution from user-writable paths."),
        PluginSpec("windows.dlllist", "execution_context", "Lists modules in each process's PEB loader lists; "
                   "identifies the main image path and DLLs loaded from unusual locations."),
        PluginSpec("windows.netscan", "network", "Pool-scans TCP/UDP endpoints and listeners with their owning "
                   "PID, including closed connections still resident in memory."),
        PluginSpec("windows.netstat", "network", "Fallback when netscan fails: walks the tcpip.sys "
                   "structures for active connections.", optional=True),
        PluginSpec("windows.malfind", "injection", "Finds VADs that are private, executable and not backed by "
                   "a file on disk - the primary memory-forensics indicator of code injection.",
                   cli_names=("windows.malware.malfind", "windows.malfind")),
        PluginSpec("windows.vadinfo", "deep_dive", "Full VAD tree for triaged processes: protections, private "
                   "vs image-backed regions and mapped files.", targeted=True),
        PluginSpec("windows.ldrmodules", "deep_dive", "Compares the three PEB loader lists against VAD mapped "
                   "images to expose unlinked (hidden) DLLs in triaged processes.", targeted=True,
                   cli_names=("windows.malware.ldrmodules", "windows.ldrmodules")),
        PluginSpec("windows.handles", "deep_dive", "Open handles of triaged processes (process, file, registry "
                   "key, mutant). Reveals e.g. handles to lsass.exe and registry persistence locations.",
                   targeted=True),
        PluginSpec("windows.getsids", "deep_dive", "Security identifiers of triaged processes - which account "
                   "the process runs as.", targeted=True),
        PluginSpec("windows.privileges", "deep_dive", "Token privileges of triaged processes (e.g. "
                   "SeDebugPrivilege enabled in a user-space process).", targeted=True),
        PluginSpec("windows.vadyarascan", "yara", "Scans process memory (VADs) with investigator-supplied YARA "
                   "rules.", targeted=True, optional=True),
        PluginSpec("windows.filescan", "files", "Scans for FILE_OBJECTs; slow on large images, so opt-in.",
                   optional=True),
    ]
}

ALLOWED_PLUGINS = frozenset(PLUGINS)
# Argument flags the pipeline is allowed to pass. Dumping/writing flags are deliberately absent.
ALLOWED_FLAGS = frozenset({"--pid", "--yara-file"})
