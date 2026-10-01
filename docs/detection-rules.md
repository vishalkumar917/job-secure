# Detection Rules & Risk Scoring

## Rule output contract

Every rule returns findings that serialise to:

```json
{
  "rule_id": "RULE_PE_IN_PRIVATE_MEMORY",
  "severity": "high",
  "finding": "svchost.exe (PID 4528) has 1 private executable region(s) that begin with a PE ('MZ') header ...",
  "evidence": [
    {"source": "windows.malfind", "artifact": "memory_region", "description": "Region starting with MZ header",
     "value": "0x1e0000-0x1fffff PAGE_EXECUTE_READWRITE tag=VadS private=True", "ref": "MEM:4528:0x1e0000"}
  ],
  "confidence": 0.8,
  "recommendation": "Dump and statically analyse the embedded PE in an isolated environment."
}
```

Findings additionally store `category`, `points` (scoring weight), ATT&CK technique IDs, the PID and an
investigator `status` (open / needs_review / confirmed / false_positive).

## Rule catalogue

| Rule ID | Category | Default sev. | Points | Requires | Logic |
|---|---|---|---|---|---|
| RULE_PROCESS_HIDING | process_integrity | high | 20 | pslist, psscan | In psscan, not pslist, no exit time |
| RULE_DUPLICATE_SYSTEM_PROCESS | process_integrity | medium | 15 | – | >1 live instance of a singleton (lsass, services, wininit…) |
| RULE_SUSPICIOUS_PARENT | parent_child | high | 15 | pslist | Unexpected parent for a system process; document/server app → shell; sensitive process → shell |
| RULE_SUSPICIOUS_PATH | path | medium | 10–25 | – | Image in Temp, Public, Recycle Bin, PerfLogs, ProgramData root, Downloads, Roaming |
| RULE_MASQUERADING | masquerading | high | 25 / 20 | – | System name at non-system path; or name within edit distance of a system binary |
| RULE_EXECUTABLE_PRIVATE_MEMORY | memory | high | 20 | malfind | Private + execute; JIT/zeroed-region adjustments |
| RULE_RWX_MEMORY | memory | medium | 10 | malfind | PAGE_EXECUTE_READWRITE / WRITECOPY |
| RULE_PE_IN_PRIVATE_MEMORY | memory | high | 25 | malfind | Region begins with `MZ` |
| RULE_SHELLCODE_INDICATOR | memory | medium | 10 | malfind | Leading bytes match documented shellcode prologues |
| RULE_UNBACKED_EXECUTABLE_VAD | memory | low | 5 | vadinfo | Extra private executable VADs not reported by malfind |
| RULE_UNLINKED_MODULE | modules | high | 20 | ldrmodules | Mapped DLL absent from InLoad/InInit/InMem |
| RULE_SUSPICIOUS_DLL_PATH | modules | medium/high | 15/20 | dlllist | DLL in staging path; core system DLL name outside system dirs (side-loading) |
| RULE_SUSPICIOUS_COMMANDLINE | commandline | per pattern | Σ patterns | – | 20 documented patterns incl. decoded `-EncodedCommand` payloads |
| RULE_SUSPICIOUS_NETWORK | network | per reason | Σ reasons | netscan | Suspicious remote/listen ports; unexpected or scripting process connecting externally |
| RULE_LSASS_ACCESS | privileges | high | 15 | handles | Non-trusted process holds PROCESS_VM_READ handle to lsass.exe |
| RULE_DEBUG_PRIVILEGE | privileges | medium | 10 | privileges | SeDebugPrivilege enabled outside the allow-list |
| RULE_YARA_MATCH | yara | rule meta | 20 | vadyarascan | YARA match; severity from `meta.severity` |
| RULE_IOC_WATCHLIST_MATCH | ioc | high | 20 | – | Remote IP, URL/domain (incl. decoded PowerShell), file name on local watchlist |

**Trust requires path.** Allow-lists (lsass handle, SeDebugPrivilege) only trust a process whose *name and
image path* match the baseline - a masquerading `C:\Users\Public\svchost.exe` does not inherit the trust of
the real `svchost.exe`.

**Rules that cannot run** (missing plugin output) are listed as *not evaluated* in the analysis summary and
report, so absence of findings is never mistaken for a clean result.

## Command-line patterns (`rules/cmdline_patterns.yaml`)

`PS_ENCODED_COMMAND`, `PS_HIDDEN_WINDOW`, `PS_EXECUTION_POLICY_BYPASS`, `PS_NO_PROFILE_NONINTERACTIVE`,
`DOWNLOAD_CRADLE`, `INVOKE_EXPRESSION`, `MSHTA_REMOTE_OR_SCRIPT`, `REGSVR32_SCRIPTLET`, `RUNDLL32_SCRIPT`,
`RUNDLL32_USER_WRITABLE_DLL`, `CERTUTIL_DOWNLOAD_DECODE`, `BITSADMIN_TRANSFER`, `WMIC_PROCESS_CREATE`,
`SCRIPT_FROM_USER_WRITABLE`, `SHADOW_COPY_DELETION`, `BOOT_RECOVERY_DISABLED`, `SCHEDULED_TASK_CREATE`,
`RUN_KEY_MODIFICATION`, `LOCAL_ACCOUNT_CREATION`, `DEFENDER_TAMPERING`. Each entry has a regex, severity,
points, ATT&CK IDs and a `why` sentence that becomes part of the finding. Base64 `-EncodedCommand` payloads
are decoded (UTF-16LE, text only - never executed) and re-scanned.

## Adding a rule

```python
# backend/app/services/detection/rules_activity.py (or a new module imported by engine.py)
@register
class UnsignedServiceRule(DetectionRule):
    rule_id = "RULE_EXAMPLE"
    title = "Example rule"
    category = "process_integrity"      # must exist in rules/scoring.yaml category_caps
    severity = "medium"
    points = 10
    attack = ["T1543.003"]
    required_plugins = ("windows.pslist",)
    description = "What it detects and why."
    explanation = {"what": "...", "why": "...", "interpretation": "...", "not_prove": "...", "next_steps": "..."}

    def evaluate(self, ctx):
        for p in ctx.processes:
            if condition(p):
                yield self.make(p, f"{p.label()} ...", [proc_evidence(p)], 0.6, "Recommendation ...")
```

On start-up the rule is inserted into the `rules` table (enable/disable from Settings), and the explanation
templates are used by the deterministic AI engine automatically. Add a positive and a negative unit test in
`backend/tests/test_detection.py`.

## Explainable risk scoring

```
contribution(f)   = round(points(f) × (0.5 + 0.5 × confidence(f)))
category_score(c) = min(cap(c), Σ contribution(f) for f in c)
bonus             = +10 if findings span ≥ 3 distinct categories
score             = min(100, Σ category_score + bonus)
```

| Band | Range |
|---|---|
| Low | 0–29 |
| Moderate | 30–59 |
| High | 60–79 |
| Critical | 80–100 |

Category caps (`rules/scoring.yaml`): process_integrity 25, parent_child 20, path 25, masquerading 25,
memory 35, modules 20, network 20, commandline 25, privileges 15, yara 25, ioc 25.

**Design rationale.**
* *Confidence-weighted*: a 0.2-confidence JIT region contributes 60 % of its points, not 100 %.
* *Caps*: many RWX regions in one browser cannot alone push a process to "critical".
* *Corroboration*: independent categories (path + memory + network + parent) agreeing is stronger evidence
  than repeated indicators of one kind - analogous to how an analyst weighs evidence.
* *Transparent*: every contribution, cap adjustment and bonus is stored as a signed contributor and shown in
  the UI and report.

Worked example (demo, PID 4528 fake `svchost.exe`):

```
+23 Process masquerading as a Windows system binary   (25 pts × conf 0.85)
+22 PE image header in private executable memory      (25 × 0.80)
+16 Executable private memory                         (20 × 0.65)
 +8 RWX region, +8 shellcode prologue, +4 unbacked VAD
-23 cap: memory category limited to 35
+16 Process executing from a user-writable directory
+13 Suspicious parent-child relationship
+12 DLL from staging directory, +12 suspicious network connection
+13 lsass handle, +8 SeDebugPrivilege, -6 privileges cap
+16 YARA match, +18 IOC watchlist match
+10 corroboration: 9 independent evidence categories
-70 cap: maximum score is 100          → 100 (critical)
```

The benign Defender process with JIT-like RWX memory scores 19 (low), demonstrating that one category of
indicator does not produce a high score.

**Disclaimer** (shown everywhere the score appears): this is the project's analytical prioritisation
model, not an authoritative malware verdict.
