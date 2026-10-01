"""Rule framework: evidence items, finding drafts, the rule base class and registry.

To add a rule: subclass :class:`DetectionRule`, set the class attributes, implement
``evaluate`` and decorate the class with ``@register``. The engine, database rule
catalogue, risk scoring and explanation layer pick it up automatically.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from app.services.analysis.process_model import ProcessView, find_parent

if TYPE_CHECKING:
    from app.services.detection.knowledge import KnowledgeBase
    from app.services.volatility.parsers import ParsedEvidence

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def max_severity(*sevs: str) -> str:
    return max(sevs, key=lambda s: SEVERITY_ORDER.get(s, 0))


@dataclass
class Evidence:
    """A single forensic artifact supporting a finding. ``source`` is the Volatility plugin."""

    source: str
    artifact: str
    description: str
    value: str
    ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FindingDraft:
    rule_id: str
    title: str
    category: str
    severity: str
    finding: str
    evidence: list[Evidence]
    confidence: float
    recommendation: str
    points: int
    attack: list[str] = field(default_factory=list)
    pid: int | None = None
    process_name: str | None = None
    process_key: str | None = None

    def to_rule_output(self) -> dict[str, Any]:
        """The canonical rule result shape documented in docs/detection-rules.md."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "finding": self.finding,
            "evidence": [e.to_dict() for e in self.evidence],
            "confidence": round(self.confidence, 2),
            "recommendation": self.recommendation,
        }


class AnalysisContext:
    """Everything a rule may look at, with convenient per-PID indexes."""

    def __init__(self, processes: list[ProcessView], evidence: ParsedEvidence, kb: KnowledgeBase):
        self.processes = processes
        self.evidence = evidence
        self.kb = kb
        self.by_pid: dict[int, list[ProcessView]] = defaultdict(list)
        for p in processes:
            self.by_pid[p.pid].append(p)
        self.modules_by_pid = _group(evidence.modules)
        self.ldr_by_pid = _group(evidence.ldrmodules)
        self.malfind_by_pid = _group(evidence.malfind)
        self.vads_by_pid = _group(evidence.vads)
        self.handles_by_pid = _group(evidence.handles)
        self.yara_by_pid = _group(evidence.yara)
        self.net_by_pid: dict[int | None, list[tuple[int, Any]]] = defaultdict(list)
        for idx, n in enumerate(evidence.network):
            self.net_by_pid[n.pid].append((idx, n))
        # Annotations written by rules and persisted by the pipeline (e.g. suspicious connection reasons).
        self.flagged_connections: dict[int, list[str]] = defaultdict(list)
        self.flagged_modules: dict[tuple[int, str], list[str]] = defaultdict(list)

    def live_process(self, pid: int | None) -> ProcessView | None:
        if pid is None:
            return None
        cands = self.by_pid.get(pid, [])
        live = [p for p in cands if not p.is_terminated]
        return (live or cands or [None])[0]

    def parent_of(self, proc: ProcessView) -> ProcessView | None:
        return find_parent(proc, self.by_pid.get(proc.ppid, []) if proc.ppid is not None else [])

    def children_of(self, proc: ProcessView) -> list[ProcessView]:
        return [p for p in self.processes if p.ppid == proc.pid and self.parent_of(p) is proc]

    def has(self, plugin: str) -> bool:
        return plugin in self.evidence.available

    def is_trusted(self, proc: ProcessView | None, allowlist: set[str]) -> bool:
        """Allow-list membership requires the name AND (where a baseline exists) the expected image path,
        so a masquerading binary cannot inherit the trust of the process it imitates."""
        if proc is None or proc.name_lc not in allowlist:
            return False
        base = self.kb.system_processes.get(proc.name_lc)
        if base and base.paths and proc.norm_path:
            return any(proc.norm_path.endswith(p) for p in base.paths)
        return True


def _group(items: list[Any]) -> dict[int, list[Any]]:
    out: dict[int, list[Any]] = defaultdict(list)
    for item in items:
        out[getattr(item, "pid", None)].append(item)
    return out


class DetectionRule(ABC):
    rule_id: ClassVar[str]
    title: ClassVar[str]
    category: ClassVar[str]
    severity: ClassVar[str]
    points: ClassVar[int]
    description: ClassVar[str]
    attack: ClassVar[list[str]] = []
    required_plugins: ClassVar[tuple[str, ...]] = ()
    # Deterministic explanation templates used by the explainable-AI layer.
    explanation: ClassVar[dict[str, str]] = {}

    @abstractmethod
    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        ...

    def make(self, proc: ProcessView | None, finding: str, evidence: list[Evidence], confidence: float,
             recommendation: str, *, severity: str | None = None, points: int | None = None,
             attack: list[str] | None = None) -> FindingDraft:
        return FindingDraft(
            rule_id=self.rule_id,
            title=self.title,
            category=self.category,
            severity=severity or self.severity,
            finding=finding,
            evidence=evidence,
            confidence=max(0.05, min(0.99, confidence)),
            recommendation=recommendation,
            points=self.points if points is None else points,
            attack=list(attack if attack is not None else self.attack),
            pid=proc.pid if proc else None,
            process_name=proc.name if proc else None,
            process_key=proc.key if proc else None,
        )

    @classmethod
    def metadata(cls) -> dict[str, Any]:
        return {"rule_id": cls.rule_id, "title": cls.title, "category": cls.category,
                "default_severity": cls.severity, "base_points": cls.points, "description": cls.description,
                "attack_techniques": list(cls.attack), "required_plugins": list(cls.required_plugins)}


RULE_REGISTRY: dict[str, type[DetectionRule]] = {}


def register(cls: type[DetectionRule]) -> type[DetectionRule]:
    if cls.rule_id in RULE_REGISTRY:
        raise ValueError(f"Duplicate rule id {cls.rule_id}")
    RULE_REGISTRY[cls.rule_id] = cls
    return cls


def proc_evidence(p: ProcessView, source: str = "windows.pslist") -> Evidence:
    return Evidence(source, "process", "Process", f"{p.name} PID {p.pid} PPID {p.ppid}", ref=f"PROC:{p.pid}")
