"""Unified process model built from multiple, independent evidence sources.

``pslist`` (OS view via ActiveProcessLinks), ``psscan`` (pool-tag scan of
physical memory) and ``pstree`` are merged. Records are joined on
(PID, CreateTime) so PID reuse does not merge two different processes. The
image path comes from the best available source: pstree's PEB path, the main
module in dlllist, or the first token of the command line - and the source is
recorded so the investigator can see where each value came from.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.services.volatility.parsers import ParsedEvidence, ProcRecord

_DEVICE_PREFIX = re.compile(r"^\\device\\harddiskvolume\d+", re.I)
_DRIVE = re.compile(r"^[a-z]:", re.I)


def normalize_path(path: str | None) -> str | None:
    """Lower-cased, drive-less Windows path suitable for matching ("\\windows\\system32\\x.exe")."""
    if not path:
        return None
    p = path.strip().strip('"').replace("/", "\\").lower()
    p = p.replace("\\??\\", "")
    p = _DEVICE_PREFIX.sub("", p)
    p = p.replace("\\systemroot\\", "\\windows\\").replace("%systemroot%", "\\windows")
    p = _DRIVE.sub("", p)
    if not p.startswith("\\"):
        p = "\\" + p
    return p


def first_token(cmdline: str | None) -> str | None:
    if not cmdline:
        return None
    s = cmdline.strip()
    if s.startswith('"'):
        end = s.find('"', 1)
        return s[1:end] if end > 0 else s[1:]
    m = re.match(r"^(.+?\.(exe|com|scr|bat|cmd))(\s|$)", s, re.I)
    return m.group(1) if m else s.split()[0]


@dataclass
class ProcessView:
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
    path_source: str | None = None
    cmdline: str | None = None
    in_pslist: bool = False
    in_psscan: bool = False
    in_pstree: bool = False
    is_hidden_candidate: bool = False
    sids: list[dict[str, Any]] = field(default_factory=list)
    privileges: list[dict[str, Any]] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.pid}|{self.create_time.isoformat() if self.create_time else '?'}"

    @property
    def name_lc(self) -> str:
        return self.name.lower()

    @property
    def norm_path(self) -> str | None:
        return normalize_path(self.path)

    @property
    def is_terminated(self) -> bool:
        return self.exit_time is not None

    @property
    def sources(self) -> list[str]:
        return [s for s, flag in (("pslist", self.in_pslist), ("psscan", self.in_psscan),
                                  ("pstree", self.in_pstree)) if flag]

    def label(self) -> str:
        return f"{self.name} (PID {self.pid})"


def _merge(view: ProcessView, rec: ProcRecord) -> None:
    for attr in ("ppid", "offset", "threads", "handles", "session_id", "wow64", "create_time", "exit_time"):
        if getattr(view, attr) is None and getattr(rec, attr) is not None:
            setattr(view, attr, getattr(rec, attr))
    if rec.path and not view.path and ("\\" in rec.path or "/" in rec.path):
        view.path, view.path_source = rec.path, "pstree (PEB image path)"
    if rec.cmdline and not view.cmdline:
        view.cmdline = rec.cmdline


def _key(rec: ProcRecord) -> str:
    return f"{rec.pid}|{rec.create_time.isoformat() if rec.create_time else '?'}"


def build_process_views(ev: ParsedEvidence) -> list[ProcessView]:
    views: dict[str, ProcessView] = {}
    for source, records in (("pslist", ev.pslist), ("psscan", ev.psscan), ("pstree", ev.pstree)):
        for rec in records:
            k = _key(rec)
            view = views.get(k)
            if view is None:
                # Tolerate a missing CreateTime in one source: join on PID + name instead.
                view = next((v for v in views.values()
                             if v.pid == rec.pid and v.name_lc[:14] == rec.name.lower()[:14]
                             and (v.create_time is None or rec.create_time is None)), None)
            if view is None:
                view = ProcessView(pid=rec.pid, ppid=rec.ppid, name=rec.name)
                views[k] = view
            _merge(view, rec)
            setattr(view, f"in_{source}", True)

    result = list(views.values())
    live_by_pid: dict[int, ProcessView] = {}
    for v in result:
        if not v.is_terminated and (v.pid not in live_by_pid or v.in_pslist):
            live_by_pid[v.pid] = v

    for c in ev.cmdlines:
        target = live_by_pid.get(c.pid)
        if target and c.args and not target.cmdline:
            target.cmdline = c.args

    # Main image path from dlllist: first module of the process whose name matches.
    first_module: dict[int, Any] = {}
    for m in ev.modules:
        if m.pid not in first_module and m.path:
            first_module[m.pid] = m
    for v in result:
        if v.path:
            continue
        mod = first_module.get(v.pid)
        if mod and not v.is_terminated and mod.name.lower()[:14] == v.name_lc[:14]:
            v.path, v.path_source = mod.path, "dlllist (main module)"
        elif v.cmdline:
            tok = first_token(v.cmdline)
            if tok and ("\\" in tok or "/" in tok):
                v.path, v.path_source = tok, "cmdline (first token)"

    # EPROCESS.ImageFileName is truncated to 14 characters; recover the full name from the path.
    for v in result:
        if v.path and len(v.name) >= 14:
            base = v.path.replace("/", "\\").split("\\")[-1]
            if base.lower().startswith(v.name_lc):
                v.name = base

    cross_view = "windows.pslist" in ev.available and "windows.psscan" in ev.available
    for v in result:
        v.is_hidden_candidate = cross_view and v.in_psscan and not v.in_pslist and not v.is_terminated

    sids = defaultdict(list)
    for s in ev.sids:
        sids[s.pid].append({"sid": s.sid, "name": s.name})
    privs = defaultdict(list)
    for p in ev.privileges:
        privs[p.pid].append({"privilege": p.privilege, "attributes": p.attributes, "enabled": p.enabled})
    for v in result:
        if v.pid in live_by_pid and live_by_pid[v.pid] is v:
            v.sids, v.privileges = sids.get(v.pid, []), privs.get(v.pid, [])

    result.sort(key=lambda v: (v.pid, v.create_time.timestamp() if v.create_time else 0))
    return result


def find_parent(child: ProcessView, candidates: list[ProcessView]) -> ProcessView | None:
    """Parent lookup that respects PID reuse: the parent must have been created before the child."""
    if child.ppid is None:
        return None
    best = None
    for c in candidates:
        if c.pid != child.ppid or c is child:
            continue
        if child.create_time and c.create_time and c.create_time > child.create_time:
            continue  # a later process that re-used the parent's PID
        if best is None or (c.create_time and best.create_time and c.create_time > best.create_time):
            best = c
    return best
