# Forensic Methodology

## Principles applied

| Principle | Implementation |
|---|---|
| **Evidence first** | Every finding carries the artifacts that support it (plugin, field, value, reference). The AI may only use stored evidence. |
| **Preserve original evidence** | Images are stored read-only under a generated name; Volatility only reads them; no dump/output plugins are permitted. |
| **Hash evidence** | SHA-256 computed during intake (single pass), re-verified before and after every analysis and on demand. |
| **Record analysis steps** | `plugin_runs` records each plugin's arguments, rationale, timing, status, error and the SHA-256 of its raw JSON output, which is kept on disk. |
| **Chain of custody** | `custody_events`: case opened, evidence received, integrity verified, analysis requested/started/completed/failed, report generated (with report hash). |
| **Separate evidence from interpretation** | Findings store *evidence* (artifacts) separately from the *finding text*; explanations have distinct "Evidence", "Possible interpretation" and "What it does NOT prove" sections. |
| **Confidence ≠ certainty** | Each finding has a rule-defined confidence (0–1) adjusted for context; the risk score is explicitly labelled an analytical prioritisation model. |
| **Reproducibility** | Same image + same rules + same Volatility version ⇒ same results. Raw plugin output hashes and the Volatility version are in the report. |
| **Show limitations** | Failed plugins, rules not evaluated (missing evidence) and generic limitations of memory forensics are listed in every report. |

## Acquisition guidance (outside this tool)

MemTrace analyses images; it does not acquire them. Recommended practice:

1. Acquire with a trusted tool (e.g. WinPmem, DumpIt, Magnet RAM Capture, FTK Imager, or a hypervisor snapshot `.vmem`).
2. Record acquisition time, tool, version, operator and the acquisition hash.
3. Upload the image and compare the MemTrace intake SHA-256 with the acquisition hash.

## Pipeline and plugin rationale

| Stage | Plugin | Why it is used |
|---|---|---|
| Identification | `windows.info` | Confirms a Windows kernel exists, resolves symbols, reports build/architecture. If this and the process listings fail, the image is reported as not analysable. |
| Process enumeration | `windows.pslist` | OS view of running processes (ActiveProcessLinks). |
| | `windows.psscan` | Pool scanning finds EPROCESS blocks unlinked from the list (DKOM) and terminated processes. |
| | `windows.pstree` | Parent/child structure; newer versions add PEB image path and command line. |
| Execution context | `windows.cmdline` | Command lines (encoded PowerShell, LOLBins, staging paths). |
| | `windows.dlllist` | Loaded modules; main image path. |
| Network | `windows.netscan` (fallback `windows.netstat`) | TCP/UDP endpoints with owning PID and creation time. |
| Injection | `windows.malware.malfind` (legacy `windows.malfind`) | Private, executable, non-file-backed VADs. |
| Triage | — | Detection pass 1 ranks processes; top `DEEP_SCAN_MAX_PIDS` plus hidden candidates are selected. |
| Deep dive (targeted `--pid`) | `windows.vadinfo` | Full VAD tree: protections, private vs mapped. |
| | `windows.malware.ldrmodules` | Mapped images vs PEB loader lists → unlinked DLLs. |
| | `windows.handles` | Process handles (e.g. to lsass.exe), registry keys, mutants. |
| | `windows.getsids`, `windows.privileges` | Account context and enabled privileges (SeDebugPrivilege). |
| Optional | `windows.vadyarascan` | Investigator YARA rules over triaged processes' memory. |
| | `windows.filescan` | Opt-in (slow): file objects in staging locations. |

The pipeline tries the current plugin name first and falls back to the legacy alias, so it works with
both older and newer Volatility 3 releases. Every plugin failure is recorded and the pipeline continues;
rules that need missing evidence are reported as "not evaluated" rather than silently passing.

## Process analysis

Records from pslist, psscan and pstree are **joined on (PID, CreateTime)** so PID reuse does not merge
two different processes. Parent lookup requires the parent to have been created *before* the child.
`EPROCESS.ImageFileName` is truncated to 14 characters; the full name is recovered from the image path.

| Observation | Interpretation offered | Caveat |
|---|---|---|
| In psscan, not in pslist, no exit time | Possible DKOM-hidden process | Live-acquisition smear; process exiting mid-capture |
| In psscan with exit time | Terminated process residue (timeline event) | Normal |
| System process with wrong parent | Masquerading / unusual spawning | PPID spoofing exists |
| Office/server app → shell/script host | Macro or exploit-driven execution | Some add-ins spawn shells |
| System binary name at non-system path | Masquerading | Third-party software with system-like names |
| Name within edit distance 1–2 of a system binary | Typo-squatting | Allow-list for legitimate look-alikes |

No process is classified as malware from its name or path alone; the score combines independent categories.

## Memory injection analysis

`malfind` regions are classified into independent indicators:

* **Executable private memory** – any private region with execute permission.
* **RWX** – `PAGE_EXECUTE_READWRITE` / `WRITECOPY`.
* **PE header in private memory** – region starts with `MZ` → reflective/manual loading indicator.
* **Shellcode prologue** – leading bytes match documented position-independent prologues.
* **Unbacked executable VAD** (vadinfo, targeted) – additional executable private regions.
* **Unlinked module** (ldrmodules) – mapped DLL absent from all three PEB loader lists.

Confidence is halved (and severity lowered) for known JIT/security processes (browsers, .NET hosts,
Defender) and lowered for regions whose leading bytes are zero (paged/uninitialised). The UI and report
state that these are *indicators*, not proof of malware.

## Network analysis

Remote addresses are classified (public, private, loopback, link-local, documentation). Heuristics from
`rules/network.yaml`: suspicious remote ports, processes that should not make external connections,
scripting/LOLBin processes connecting out, listeners on backdoor-associated ports, and matches against the
local watchlist (`rules/ioc_watchlist.yaml`). **No IP is called malicious without external evidence**;
threat-intelligence enrichment is a pluggable extension point (the local watchlist is the implemented provider).

## Timeline

Only timestamps present in memory structures are used: EPROCESS CreateTime/ExitTime, TCP endpoint
creation time and LDR LoadTime (for suspicious modules). Findings have no intrinsic time: they are anchored
to the owning process creation time (and labelled as such) or listed as "timestamp unavailable". All times
are UTC.

## Limitations of memory forensics (also printed in every report)

* A RAM image is a single point in time; earlier activity may not be resident.
* Paged-out memory is absent; command lines, modules or VAD content may be missing.
* Live acquisition can produce smear (inconsistent kernel structures).
* Heuristics and signatures produce indicators requiring corroboration, not verdicts.
* Rootkits can tamper with the structures Volatility reads.
* The risk score is the project's analytical model, not an authoritative verdict.

## Using a legitimate test memory image

Use only images you are authorised to analyse. Options:

1. **Your own lab VM**: run a Windows 10/11 VM, pause it and use the `.vmem` (VMware) file, or capture with
   WinPmem/DumpIt inside the VM. Optionally run benign "suspicious-looking" activity (e.g. an encoded
   PowerShell `Write-Output` command, a copy of `notepad.exe` in `C:\Users\Public`) to exercise rules safely.
2. **Public training images** published for forensic education, such as the Volatility Foundation's memory
   samples list and the samples accompanying *The Art of Memory Forensics*, or memory images released with
   public DFIR CTF challenges. Check each source's licence and terms.
3. Volatility needs the matching Windows symbol table. With internet access it is downloaded automatically
   (cached in `~/.cache/volatility3`); for offline work place symbol packs in `VOLATILITY_SYMBOLS_DIR` and
   set `VOLATILITY_OFFLINE=true`.
