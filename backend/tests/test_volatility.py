"""Volatility parsers, identification and the hardened subprocess runner."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from app.services.volatility import parsers as vp
from app.services.volatility.identification import identify
from app.services.volatility.runner import VolatilityRunner, explain_volatility_error, flatten_tree

FIX = Path(__file__).parent / "fixtures"


def load(name: str):
    return json.loads((FIX / "volatility" / name).read_text())


# ------------------------------------------------------------------ parsers
def test_process_parser_handles_variants_and_absent_values():
    procs = vp.parse_processes(load("pslist_variant.json"))
    assert [p.pid for p in procs] == [4, 700, 812]  # row with PID "N/A" skipped
    system, services, long_name = procs
    assert system.session_id is None and system.handles is None
    assert system.offset == hex(18446708889337476992)  # >64-bit-signed address kept as hex string
    assert services.offset == "0xffff8a0012345080"
    assert services.create_time.isoformat() == "2024-05-01T09:00:05+00:00"
    assert services.exit_time is None  # zeroed FILETIME (1601) treated as absent
    assert long_name.wow64 is True and long_name.create_time.tzinfo is not None


def test_flatten_tree_preserves_children():
    rows = flatten_tree(load("pstree_nested.json"))
    assert [(r["PID"], r["__depth"]) for r in rows] == [(4, 0), (300, 1)]
    procs = vp.parse_processes(rows)
    assert procs[1].path == "C:\\Windows\\System32\\smss.exe"


def test_malfind_hexdump_parsing_and_pe_detection():
    regions = vp.parse_regions(load("malfind_sample.json"))
    assert regions[0].has_pe_header and regions[0].first_bytes[:2] == b"MZ"
    assert regions[0].start == "0x1f0000"
    assert regions[1].start == "0x2a0000" and not regions[1].has_pe_header
    assert regions[1].first_bytes.startswith(b"\xfc\x48\x83\xe4\xf0")
    assert regions[2].first_bytes == b"\x00" * 16


def test_cmdline_parser_drops_volatility_diagnostics():
    rows = [{"PID": 1, "Process": "a", "Args": "Required memory at 0x1 is not valid"},
            {"PID": 2, "Process": "b", "Args": "b.exe -x"}]
    out = vp.parse_cmdline(rows)
    assert out[0].args is None and out[1].args == "b.exe -x"


def test_privileges_enabled_flag():
    rows = [{"PID": 5, "Process": "p", "Privilege": "SeDebugPrivilege", "Attributes": "Present,Enabled"},
            {"PID": 5, "Process": "p", "Privilege": "SeShutdownPrivilege", "Attributes": "Present"}]
    privs = vp.parse_privileges(rows)
    assert privs[0].enabled and not privs[1].enabled


def test_unhashable_values_do_not_crash_parsers():
    assert vp.get({"PID": [1, 2]}, "PID") == [1, 2]
    assert vp.to_int({"x": 1}) is None


# ------------------------------------------------------------------ identification
def test_identify_windows10_x64():
    info = {"Is64Bit": True, "IsPAE": False, "NtMajorVersion": 10, "NtMinorVersion": 0, "Major/Minor": "15.19041",
            "NtProductType": "NtProductWinNt", "Kernel Base": 0xF80250000000,
            "Symbols": "file:///s/windows/ntkrnlmp.pdb/9B2F0A4E7C1D4E2A8F3B6C5D4E3F2A1B-1.json.xz"}
    r = identify(info)
    assert r["os_name"] == "Windows 10" and r["build"] == 19041 and r["architecture"] == "x64"
    assert r["confidence"] == "high" and r["kernel_base"] == "0xf80250000000"
    assert r["suggested_symbols"].startswith("ntkrnlmp.pdb 9B2F0A4E")


def test_identify_server_and_win11():
    assert identify({"NtMajorVersion": 10, "NtMinorVersion": 0, "Major/Minor": "15.17763",
                     "NtProductType": "NtProductServer", "Is64Bit": True})["os_name"] == "Windows Server 2019"
    assert identify({"NtMajorVersion": 10, "NtMinorVersion": 0, "Major/Minor": "15.22631",
                     "NtProductType": "NtProductWinNt", "Is64Bit": True})["os_name"] == "Windows 11"


def test_identify_reports_uncertainty_instead_of_guessing():
    r = identify({}, ["Header: Windows kernel crash dump (64-bit, PAGEDU64)."])
    assert r["os_name"] is None and r["confidence"] == "low"
    assert "os_name" in r["uncertain"] and r["architecture"].startswith("x64")
    r2 = identify({"Is64Bit": True})
    assert r2["os_name"] is None and "build" in r2["uncertain"]


# ------------------------------------------------------------------ runner
@pytest.fixture
def fake_runner(settings, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "volatility_cmd", f'"{sys.executable}" "{FIX / "fake_vol.py"}"')
    monkeypatch.setattr(settings, "plugin_timeout_seconds", 3)
    image = settings.evidence_dir / "runner_test.raw"
    if not image.exists():
        image.write_bytes(b"\x00" * 4096)
    return VolatilityRunner(settings, tmp_path), image


def test_runner_parses_json_and_records_output_hash(fake_runner):
    runner, image = fake_runner
    res = runner.run(image, "windows.pslist")
    assert res.ok and [r["PID"] for r in res.rows] == [4, 300]
    assert res.output_sha256 and Path(res.output_path).exists()


def test_runner_translates_symbol_errors(fake_runner):
    runner, image = fake_runner
    res = runner.run(image, "windows.info")
    assert res.status == "failed" and "symbol" in res.error.lower()


def test_runner_timeout_kills_process(fake_runner):
    runner, image = fake_runner
    res = runner.run(image, "windows.psscan")
    assert res.status == "timeout" and "timeout" in res.error


def test_runner_falls_back_to_legacy_plugin_name(fake_runner):
    runner, image = fake_runner
    res = runner.run(image, "windows.malfind")  # new name unknown to fake vol -> legacy alias
    assert res.ok and res.rows[0]["Process"] == "x"


def test_runner_strips_secrets_from_environment(fake_runner, monkeypatch):
    runner, image = fake_runner
    monkeypatch.setenv("AI_API_KEY", "sk-should-not-leak")
    monkeypatch.setenv("MY_SECRET_TOKEN", "x")
    res = runner.run(image, "windows.cmdline")
    assert res.rows[0]["Args"] == "clean"


def test_runner_rejects_unlisted_plugins_and_foreign_paths(fake_runner, tmp_path):
    runner, image = fake_runner
    assert runner.run(image, "windows.dumpfiles").status == "failed"
    outside = tmp_path / "outside.raw"
    outside.write_bytes(b"\x00")
    assert "outside the evidence store" in runner.run(outside, "windows.pslist").error
    evil_rule = tmp_path.parent / "evil.yar"
    evil_rule.write_text("rule x { condition: true }")
    res = runner.run(image, "windows.vadyarascan", yara_file=evil_rule)
    assert res.status == "failed" and "YARA" in res.error


def test_runner_pid_arguments_are_sanitised(fake_runner):
    runner, _ = fake_runner
    args = runner._validate_args("windows.handles", [5, 5, 3, -1 + 1, 2**33], None)
    assert args == ["--pid", "0", "3", "5"]


def test_explain_error_messages():
    assert "symbol" in explain_volatility_error("Unsatisfied requirement plugins.PsList.kernel.symbol_table_name")
    assert "corrupted" in explain_volatility_error("Unable to validate the plugin requirements: ['x']")
