"""Detection engine: runs every enabled rule with per-rule fault isolation.

A rule that raises is logged and skipped - it never aborts the analysis. Rules
whose required plugins produced no output are recorded as "not evaluated" so the
report can state this limitation instead of implying a clean result.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.logging import get_logger
from app.services.detection import rules_activity, rules_memory, rules_process  # noqa: F401 - register rules
from app.services.detection.base import RULE_REGISTRY, AnalysisContext, FindingDraft

log = get_logger(__name__)


@dataclass
class DetectionResult:
    findings: list[FindingDraft] = field(default_factory=list)
    not_evaluated: dict[str, str] = field(default_factory=dict)  # rule_id -> reason
    errors: dict[str, str] = field(default_factory=dict)


class DetectionEngine:
    def __init__(self, enabled_rules: set[str] | None = None):
        self.enabled_rules = enabled_rules

    def run(self, ctx: AnalysisContext) -> DetectionResult:
        result = DetectionResult()
        for rule_id, rule_cls in RULE_REGISTRY.items():
            if self.enabled_rules is not None and rule_id not in self.enabled_rules:
                result.not_evaluated[rule_id] = "disabled by investigator"
                continue
            missing = [p for p in rule_cls.required_plugins if not ctx.has(p)]
            if missing:
                result.not_evaluated[rule_id] = f"required evidence unavailable ({', '.join(missing)})"
                continue
            try:
                result.findings.extend(rule_cls().evaluate(ctx))
            except Exception as exc:  # noqa: BLE001 - isolate faulty rules
                log.exception("detection rule failed", extra={"rule_id": rule_id})
                result.errors[rule_id] = f"{type(exc).__name__}: {exc}"
        return result


def rule_catalog() -> list[dict]:
    return [cls.metadata() for cls in RULE_REGISTRY.values()]
