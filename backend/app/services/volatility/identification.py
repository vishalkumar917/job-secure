"""Memory image identification from ``windows.info`` output.

Only facts that Volatility actually reported are used. Where a value cannot be
derived it is reported as ``None`` and listed under ``uncertain`` so the UI and
report can say "unknown" instead of guessing.
"""

from __future__ import annotations

import re
from typing import Any

from app.services.volatility.parsers import to_bool, to_int


def _windows_name(major: int, minor: int, build: int | None, product_type: str | None) -> str | None:
    server = bool(product_type) and "winnt" not in product_type.lower()
    if (major, minor) == (10, 0):
        if build is None:
            return "Windows 10/11 or Server 2016+ (build unknown)"
        if server:
            if build >= 26100:
                return "Windows Server 2025"
            if build >= 20348:
                return "Windows Server 2022"
            if build >= 17763:
                return "Windows Server 2019"
            return "Windows Server 2016"
        return "Windows 11" if build >= 22000 else "Windows 10"
    table = {
        (6, 3): ("Windows 8.1", "Windows Server 2012 R2"),
        (6, 2): ("Windows 8", "Windows Server 2012"),
        (6, 1): ("Windows 7", "Windows Server 2008 R2"),
        (6, 0): ("Windows Vista", "Windows Server 2008"),
        (5, 2): ("Windows XP x64", "Windows Server 2003"),
        (5, 1): ("Windows XP", "Windows XP"),
    }
    names = table.get((major, minor))
    if not names:
        return None
    return names[1] if server else names[0]


def identify(info: dict[str, Any], header_notes: list[str] | None = None) -> dict[str, Any]:
    uncertain: list[str] = []
    result: dict[str, Any] = {
        "os_name": None, "nt_version": None, "build": None, "architecture": None, "kernel_base": None,
        "dtb": None, "symbols": None, "suggested_symbols": None, "system_time": None,
        "processors": None, "product_type": None, "system_root": None, "confidence": "low",
        "uncertain": uncertain, "source": "windows.info",
    }
    if not info:
        result["source"] = "unavailable"
        result["uncertain"] = ["os_name", "architecture", "kernel", "build"]
        result["note"] = ("windows.info did not produce output; the operating system could not be identified "
                          "from this image.")
        if header_notes:
            for note in header_notes:
                if "64-bit" in note:
                    result["architecture"] = "x64 (from crash-dump header)"
                elif "32-bit" in note:
                    result["architecture"] = "x86 (from crash-dump header)"
        return result

    is64 = to_bool(info.get("Is64Bit"))
    is_pae = to_bool(info.get("IsPAE"))
    if is64 is True:
        result["architecture"] = "x64"
    elif is64 is False:
        result["architecture"] = "x86 (PAE)" if is_pae else "x86"
    else:
        uncertain.append("architecture")

    major = to_int(info.get("NtMajorVersion"))
    minor = to_int(info.get("NtMinorVersion"))
    if major is None:
        major = to_int(info.get("PE MajorOperatingSystemVersion"))
        minor = to_int(info.get("PE MinorOperatingSystemVersion"))
        if major is not None:
            uncertain.append("nt_version (derived from kernel PE header)")

    build = None
    mm = info.get("Major/Minor")
    if isinstance(mm, str) and "." in mm:
        build = to_int(mm.split(".")[-1])
    if build is None:
        uncertain.append("build")

    product_type = info.get("NtProductType")
    result["product_type"] = product_type
    if major is not None and minor is not None:
        result["nt_version"] = f"{major}.{minor}"
        result["os_name"] = _windows_name(major, minor, build, product_type)
    if result["os_name"] is None:
        uncertain.append("os_name")
    result["build"] = build

    kb = info.get("Kernel Base")
    result["kernel_base"] = hex(kb) if isinstance(kb, int) else kb
    dtb = info.get("DTB")
    result["dtb"] = hex(dtb) if isinstance(dtb, int) else dtb
    result["system_time"] = info.get("SystemTime")
    result["processors"] = to_int(info.get("KeNumberProcessors"))
    result["system_root"] = info.get("NtSystemRoot")

    symbols = info.get("Symbols")
    result["symbols"] = symbols
    if isinstance(symbols, str):
        m = re.search(r"([\w.]+\.pdb)[/\\]([0-9A-Fa-f]{32,33}-?\d*)", symbols)
        if m:
            result["suggested_symbols"] = f"{m.group(1)} {m.group(2)}"
    if result["suggested_symbols"] is None:
        result["suggested_symbols"] = ("Kernel PDB GUID not reported; obtain the ntkrnlmp.pdb symbol table "
                                       "matching this build (Volatility downloads it automatically when online).")
        uncertain.append("symbols")

    if result["os_name"] and build and result["architecture"]:
        result["confidence"] = "high"
    elif result["os_name"] or result["architecture"]:
        result["confidence"] = "medium"
    return result
