"""Explainable process risk scoring (project analytical model, not a malware verdict).

    contribution(f)   = round(points(f) * (0.5 + 0.5 * confidence(f)))
    category_score(c) = min(cap(c), sum(contribution(f) for f in category c))
    bonus             = corroboration bonus if >= N distinct categories fired
    score             = min(100, sum(category_score) + bonus)

Every step is returned as a list of signed contributors so the UI and report can
show *exactly* why a process received its score, e.g.

    +25 PE image header in private executable memory
    +17 Executable private memory
    -7  cap: memory category limited to 35
    +10 corroboration: 4 independent evidence categories
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from app.services.detection.base import FindingDraft

DEFAULT_CAPS = {"process_integrity": 25, "parent_child": 20, "path": 25, "masquerading": 25, "memory": 35,
                "modules": 20, "network": 20, "commandline": 25, "privileges": 15, "yara": 25, "ioc": 25}
DEFAULT_BANDS = [("low", 0, 29), ("moderate", 30, 59), ("high", 60, 79), ("critical", 80, 100)]


@dataclass
class ScoringModel:
    caps: dict[str, int]
    min_categories: int
    bonus: int
    bands: list[tuple[str, int, int]]

    @classmethod
    def from_config(cls, cfg: dict[str, Any] | None) -> ScoringModel:
        cfg = cfg or {}
        caps = {**DEFAULT_CAPS, **{k: int(v) for k, v in (cfg.get("category_caps") or {}).items()}}
        corr = cfg.get("corroboration") or {}
        bands = [(b["name"], int(b["min"]), int(b["max"])) for b in cfg.get("bands") or []] or DEFAULT_BANDS
        return cls(caps, int(corr.get("min_categories", 3)), int(corr.get("bonus", 10)), bands)

    def band(self, score: int) -> str:
        for name, lo, hi in self.bands:
            if lo <= score <= hi:
                return name
        return self.bands[-1][0]

    def describe(self) -> dict[str, Any]:
        return {
            "formula": "contribution = round(points x (0.5 + 0.5 x confidence)); category totals capped; "
                       f"+{self.bonus} corroboration bonus when findings span >= {self.min_categories} categories; "
                       "score capped at 100",
            "category_caps": self.caps,
            "corroboration": {"min_categories": self.min_categories, "bonus": self.bonus},
            "bands": [{"name": n, "min": lo, "max": hi} for n, lo, hi in self.bands],
            "disclaimer": "Analytical prioritisation score produced by this project's model. It is not an "
                          "authoritative malware verdict.",
        }


def contribution(f: FindingDraft) -> int:
    return round(f.points * (0.5 + 0.5 * f.confidence))


def score_findings(findings: list[FindingDraft], model: ScoringModel) -> tuple[int, str, list[dict[str, Any]]]:
    contributors: list[dict[str, Any]] = []
    by_cat: dict[str, list[FindingDraft]] = defaultdict(list)
    for f in findings:
        if f.points > 0:
            by_cat[f.category].append(f)

    total = 0
    for cat, items in sorted(by_cat.items()):
        cat_sum = 0
        for f in sorted(items, key=contribution, reverse=True):
            pts = contribution(f)
            cat_sum += pts
            contributors.append({"points": pts, "label": f.title, "rule_id": f.rule_id, "category": cat,
                                 "base_points": f.points, "confidence": round(f.confidence, 2)})
        cap = model.caps.get(cat, 25)
        if cat_sum > cap:
            contributors.append({"points": cap - cat_sum, "label": f"cap: {cat} category limited to {cap}",
                                 "rule_id": None, "category": cat})
            cat_sum = cap
        total += cat_sum

    if len(by_cat) >= model.min_categories:
        contributors.append({"points": model.bonus, "rule_id": None, "category": "corroboration",
                             "label": f"corroboration: {len(by_cat)} independent evidence categories"})
        total += model.bonus

    if total > 100:
        contributors.append({"points": 100 - total, "label": "cap: maximum score is 100", "rule_id": None,
                             "category": "cap"})
        total = 100
    return total, model.band(total), contributors


def score_processes(findings: list[FindingDraft], model: ScoringModel) -> dict[str, tuple[int, str, list]]:
    """Score every process key that has at least one finding."""
    grouped: dict[str, list[FindingDraft]] = defaultdict(list)
    for f in findings:
        if f.process_key:
            grouped[f.process_key].append(f)
    return {key: score_findings(items, model) for key, items in grouped.items()}
