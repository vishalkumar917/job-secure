"""Loads the YAML knowledge base in ``rules/`` (baselines, patterns, scoring, watchlist)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


@dataclass
class SystemProcessBaseline:
    name: str
    paths: list[str]
    parents: list[str]
    allow_orphan: bool
    singleton: bool


@dataclass
class PathPattern:
    regex: re.Pattern[str]
    label: str
    severity: str
    points: int


@dataclass
class CmdlinePattern:
    id: str
    regex: re.Pattern[str]
    severity: str
    points: int
    why: str
    attack: list[str]


@dataclass
class KnowledgeBase:
    system_processes: dict[str, SystemProcessBaseline]
    document_apps: set[str]
    shells: set[str]
    sensitive_parents: set[str]
    path_patterns: list[PathPattern]
    jit_processes: set[str]
    lsass_allowlist: set[str]
    debug_allowlist: set[str]
    system_dlls: set[str]
    system_dll_dirs: list[str]
    lookalike_allowlist: set[str]
    cmdline_patterns: list[CmdlinePattern]
    suspicious_ports: dict[int, str]
    unexpected_network: set[str]
    scripting_network: set[str]
    scoring: dict[str, Any]
    watchlist: dict[str, dict[str, str]] = field(default_factory=dict)  # type -> value -> label
    yara_severity: dict[str, str] = field(default_factory=dict)


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_knowledge_base(rules_dir: Path) -> KnowledgeBase:
    base = _load(rules_dir / "baselines.yaml")
    cmd = _load(rules_dir / "cmdline_patterns.yaml")
    net = _load(rules_dir / "network.yaml")
    scoring = _load(rules_dir / "scoring.yaml")
    wl = _load(rules_dir / "ioc_watchlist.yaml")

    procs = {
        name.lower(): SystemProcessBaseline(
            name=name.lower(),
            paths=[p.lower() for p in (spec.get("paths") or [])],
            parents=[p.lower() for p in (spec.get("parents") or [])],
            allow_orphan=bool(spec.get("allow_orphan", False)),
            singleton=bool(spec.get("singleton", False)),
        )
        for name, spec in (base.get("system_processes") or {}).items()
    }
    watchlist: dict[str, dict[str, str]] = {}
    for key, ioc_type in (("ipv4", "ipv4"), ("domains", "domain"), ("sha256", "sha256"), ("file_names", "file_name")):
        watchlist[ioc_type] = {str(e["value"]).lower(): str(e.get("label", "")) for e in (wl.get(key) or [])
                               if isinstance(e, dict) and "value" in e}

    return KnowledgeBase(
        system_processes=procs,
        document_apps={x.lower() for x in base.get("document_and_browser_apps") or []},
        shells={x.lower() for x in base.get("shells_and_script_hosts") or []},
        sensitive_parents={x.lower() for x in base.get("sensitive_parents") or []},
        path_patterns=[PathPattern(re.compile(p["pattern"], re.I), p["label"], p["severity"], int(p["points"]))
                       for p in base.get("suspicious_path_patterns") or []],
        jit_processes={x.lower() for x in base.get("jit_or_security_processes") or []},
        lsass_allowlist={x.lower() for x in base.get("lsass_handle_allowlist") or []},
        debug_allowlist={x.lower() for x in base.get("debug_privilege_allowlist") or []},
        system_dlls={x.lower() for x in base.get("system_dlls") or []},
        system_dll_dirs=[x.lower() for x in base.get("system_dll_dirs") or []],
        lookalike_allowlist={x.lower() for x in base.get("lookalike_allowlist") or
                             ["taskhost.exe", "taskhostex.exe", "taskhostw.exe", "svchost.exe"]},
        cmdline_patterns=[CmdlinePattern(p["id"], re.compile(p["regex"], re.I), p["severity"], int(p["points"]),
                                         p["why"], list(p.get("attack") or [])) for p in cmd.get("patterns") or []],
        suspicious_ports={int(k): str(v) for k, v in (net.get("suspicious_remote_ports") or {}).items()},
        unexpected_network={x.lower() for x in net.get("unexpected_network_processes") or []},
        scripting_network={x.lower() for x in net.get("scripting_network_processes") or []},
        scoring=scoring,
        watchlist=watchlist,
    )


@lru_cache(maxsize=4)
def cached_knowledge_base(rules_dir: str) -> KnowledgeBase:
    return load_knowledge_base(Path(rules_dir))
