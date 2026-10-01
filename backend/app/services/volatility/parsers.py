"""Normalise Volatility 3 JSON rows into typed records.

Column names differ slightly across Volatility 3 releases (e.g. ``Offset(V)``
vs ``Offset``, ``Process`` vs ``ImageFileName``), and absent values are
rendered as ``null`` or ``"N/A"``. Every parser therefore looks up a field by a
list of aliases and treats absent values as ``None`` - nothing is invented.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

_ABSENT_STR = {"", "N/A", "-", "Unreadable", "NotAvailable", "NotApplicable"}


def is_absent(value: Any) -> bool:
    return value is None or (isinstance(value, str) and value.strip() in _ABSENT_STR)


def get(row: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in row and not is_absent(row[k]):
            return row[k]
    return None


def to_int(value: Any) -> int | None:
    if is_absent(value):
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        s = str(value).strip()
        return int(s, 16) if s.lower().startswith("0x") else int(float(s))
    except (TypeError, ValueError):
        return None


def to_hex(value: Any) -> str | None:
    n = to_int(value)
    return None if n is None else hex(n)


def to_bool(value: Any) -> bool | None:
    if is_absent(value):
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    s = str(value).strip().lower()
    if s in {"true", "1", "yes"}:
        return True
    if s in {"false", "0", "no"}:
        return False
    return None


_DT_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S")


def to_datetime(value: Any) -> datetime | None:
    if is_absent(value):
        return None
    s = str(value).strip().replace(" UTC", "").replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        dt = None
        for fmt in _DT_FORMATS:
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    # Volatility renders a zeroed FILETIME as 1601-01-01; treat as absent.
    if dt.year < 1980:
        return None
    return dt.astimezone(timezone.utc)


# --------------------------------------------------------------------------- records
@dataclass
class ProcRecord:
    pid: int
    ppid: int | None
    name: str
    offset: str | None = None
    threads: int | None = None
    handles: int | None = None
    session_id: int | None = None
    wow64: bool | None = None
    create_time: datetime | None = None
    exit_time: datetime | None = None
    path: str | None = None
    cmdline: str | None = None


@dataclass
class CmdlineRecord:
    pid: int
    process: str | None
    args: str | None


@dataclass
class ModuleRecord:
    pid: int
    process: str | None
    name: str
    path: str | None
    base: str | None
    size: int | None
    load_time: datetime | None = None


@dataclass
class LdrModuleRecord:
    pid: int
    process: str | None
    base: str | None
    in_load: bool | None
    in_init: bool | None
    in_mem: bool | None
    mapped_path: str | None


@dataclass
class RegionRecord:
    pid: int
    process: str | None
    start: str
    end: str
    protection: str | None
    tag: str | None
    private_memory: bool | None
    commit_charge: int | None
    mapped_file: str | None = None
    hexdump: str | None = None
    disasm: str | None = None
    notes: str | None = None
    has_pe_header: bool = False
    first_bytes: bytes = b""


@dataclass
class NetRecord:
    protocol: str
    local_addr: str | None
    local_port: int | None
    foreign_addr: str | None
    foreign_port: int | None
    state: str | None
    pid: int | None
    owner: str | None
    created: datetime | None
    offset: str | None


@dataclass
class HandleRec:
    pid: int
    process: str | None
    handle_value: str | None
    handle_type: str | None
    granted_access: str | None
    name: str | None


@dataclass
class SidRecord:
    pid: int
    process: str | None
    sid: str
    name: str | None


@dataclass
class PrivilegeRecord:
    pid: int
    process: str | None
    privilege: str
    attributes: str
    enabled: bool
    description: str | None = None


@dataclass
class YaraRecord:
    pid: int | None
    rule: str
    offset: str | None
    component: str | None
    value: str | None


@dataclass
class ParsedEvidence:
    info: dict[str, Any] = field(default_factory=dict)
    pslist: list[ProcRecord] = field(default_factory=list)
    psscan: list[ProcRecord] = field(default_factory=list)
    pstree: list[ProcRecord] = field(default_factory=list)
    cmdlines: list[CmdlineRecord] = field(default_factory=list)
    modules: list[ModuleRecord] = field(default_factory=list)
    ldrmodules: list[LdrModuleRecord] = field(default_factory=list)
    malfind: list[RegionRecord] = field(default_factory=list)
    vads: list[RegionRecord] = field(default_factory=list)
    network: list[NetRecord] = field(default_factory=list)
    handles: list[HandleRec] = field(default_factory=list)
    sids: list[SidRecord] = field(default_factory=list)
    privileges: list[PrivilegeRecord] = field(default_factory=list)
    yara: list[YaraRecord] = field(default_factory=list)
    available: set[str] = field(default_factory=set)  # plugins that produced output


# --------------------------------------------------------------------------- parsers
def parse_info(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for row in rows:
        var = get(row, "Variable")
        if var is not None:
            out[str(var)] = row.get("Value")
    return out


def parse_processes(rows: list[dict[str, Any]]) -> list[ProcRecord]:
    procs: list[ProcRecord] = []
    for row in rows:
        pid = to_int(get(row, "PID", "Pid"))
        if pid is None:
            continue
        procs.append(ProcRecord(
            pid=pid,
            ppid=to_int(get(row, "PPID", "PPid")),
            name=str(get(row, "ImageFileName", "Name", "Process") or f"pid_{pid}"),
            offset=to_hex(get(row, "Offset(V)", "Offset(P)", "Offset")),
            threads=to_int(get(row, "Threads")),
            handles=to_int(get(row, "Handles")),
            session_id=to_int(get(row, "SessionId")),
            wow64=to_bool(get(row, "Wow64")),
            create_time=to_datetime(get(row, "CreateTime")),
            exit_time=to_datetime(get(row, "ExitTime")),
            path=_str(get(row, "Path", "Audit")),
            cmdline=_str(get(row, "Cmd")),
        ))
    return procs


def parse_cmdline(rows: list[dict[str, Any]]) -> list[CmdlineRecord]:
    out = []
    for row in rows:
        pid = to_int(get(row, "PID", "Pid"))
        if pid is None:
            continue
        args = get(row, "Args")
        # Volatility emits explanatory text such as "Required memory at 0x... is not valid" when the
        # PEB is paged out; that is not a command line.
        if isinstance(args, str) and args.lower().startswith(("required memory", "process ")):
            args = None
        out.append(CmdlineRecord(pid, _str(get(row, "Process", "ImageFileName")), _str(args)))
    return out


def parse_dlllist(rows: list[dict[str, Any]]) -> list[ModuleRecord]:
    out = []
    for row in rows:
        pid = to_int(get(row, "PID", "Pid"))
        name = get(row, "Name")
        if pid is None or name is None:
            continue
        out.append(ModuleRecord(pid, _str(get(row, "Process")), str(name), _str(get(row, "Path")),
                                to_hex(get(row, "Base")), to_int(get(row, "Size")),
                                to_datetime(get(row, "LoadTime"))))
    return out


def parse_ldrmodules(rows: list[dict[str, Any]]) -> list[LdrModuleRecord]:
    out = []
    for row in rows:
        pid = to_int(get(row, "Pid", "PID"))
        if pid is None:
            continue
        out.append(LdrModuleRecord(pid, _str(get(row, "Process")), to_hex(get(row, "Base")),
                                   to_bool(row.get("InLoad")), to_bool(row.get("InInit")),
                                   to_bool(row.get("InMem")), _str(get(row, "MappedPath"))))
    return out


_HEX_BYTE = re.compile(r"\b([0-9a-fA-F]{2})\b")


def hexdump_bytes(hexdump: str | None, limit: int = 64) -> bytes:
    """Extract the leading bytes from a Volatility hexdump string (ignores the ASCII column)."""
    if not hexdump:
        return b""
    data = bytearray()
    for line in str(hexdump).splitlines():
        # Hex column is everything before the double-space ASCII gutter.
        hex_part = re.split(r"\s{2,}", line.strip())[0]
        for m in _HEX_BYTE.finditer(hex_part):
            data.append(int(m.group(1), 16))
            if len(data) >= limit:
                return bytes(data)
    return bytes(data)


def _parse_region(row: dict[str, Any]) -> RegionRecord | None:
    pid = to_int(get(row, "PID", "Pid"))
    start = to_hex(get(row, "Start VPN", "Start"))
    if pid is None or start is None:
        return None
    hexdump = _str(get(row, "Hexdump"))
    first = hexdump_bytes(hexdump)
    return RegionRecord(
        pid=pid,
        process=_str(get(row, "Process")),
        start=start,
        end=to_hex(get(row, "End VPN", "End")) or start,
        protection=_str(get(row, "Protection")),
        tag=_str(get(row, "Tag")),
        private_memory=to_bool(get(row, "PrivateMemory")),
        commit_charge=to_int(get(row, "CommitCharge")),
        mapped_file=_str(get(row, "File")),
        hexdump=hexdump,
        disasm=_str(get(row, "Disasm")),
        notes=_str(get(row, "Notes")),
        has_pe_header=first[:2] == b"MZ",
        first_bytes=first,
    )


def parse_regions(rows: list[dict[str, Any]]) -> list[RegionRecord]:
    return [r for r in (_parse_region(row) for row in rows) if r is not None]


def parse_netscan(rows: list[dict[str, Any]]) -> list[NetRecord]:
    out = []
    for row in rows:
        proto = get(row, "Proto", "Protocol")
        if proto is None:
            continue
        out.append(NetRecord(
            protocol=str(proto),
            local_addr=_str(get(row, "LocalAddr")),
            local_port=to_int(get(row, "LocalPort")),
            foreign_addr=_str(get(row, "ForeignAddr")),
            foreign_port=to_int(get(row, "ForeignPort")),
            state=_str(get(row, "State")),
            pid=to_int(get(row, "PID", "Pid")),
            owner=_str(get(row, "Owner")),
            created=to_datetime(get(row, "Created")),
            offset=to_hex(get(row, "Offset")),
        ))
    return out


def parse_handles(rows: list[dict[str, Any]]) -> list[HandleRec]:
    out = []
    for row in rows:
        pid = to_int(get(row, "PID", "Pid"))
        if pid is None:
            continue
        out.append(HandleRec(pid, _str(get(row, "Process")), to_hex(get(row, "HandleValue")),
                             _str(get(row, "Type")), to_hex(get(row, "GrantedAccess")), _str(get(row, "Name"))))
    return out


def parse_sids(rows: list[dict[str, Any]]) -> list[SidRecord]:
    out = []
    for row in rows:
        pid = to_int(get(row, "PID", "Pid"))
        sid = get(row, "SID")
        if pid is None or sid is None:
            continue
        out.append(SidRecord(pid, _str(get(row, "Process")), str(sid), _str(get(row, "Name"))))
    return out


def parse_privileges(rows: list[dict[str, Any]]) -> list[PrivilegeRecord]:
    out = []
    for row in rows:
        pid = to_int(get(row, "PID", "Pid"))
        priv = get(row, "Privilege")
        if pid is None or priv is None:
            continue
        attrs = str(get(row, "Attributes") or "")
        out.append(PrivilegeRecord(pid, _str(get(row, "Process")), str(priv), attrs,
                                   "enabled" in attrs.lower(), _str(get(row, "Description"))))
    return out


def parse_yara(rows: list[dict[str, Any]]) -> list[YaraRecord]:
    out = []
    for row in rows:
        rule = get(row, "Rule")
        if rule is None:
            continue
        value = row.get("Value")
        if isinstance(value, (bytes, bytearray)):
            value = value.hex()
        out.append(YaraRecord(to_int(get(row, "PID", "Pid", "Owner")), str(rule),
                              to_hex(get(row, "Offset")), _str(get(row, "Component")), _str(value)))
    return out


def _str(value: Any) -> str | None:
    if is_absent(value):
        return None
    return str(value)
