"""Evidence Retriever: selects the evidence relevant to a question.

Retrieval is hybrid:
1. Intent classification (summary, injection, network, parent/child, ...).
2. Entity extraction (PIDs, process names, IPs, finding IDs) with structured
   look-ups - e.g. "Why is PID 4528 suspicious?" pulls the process, its
   findings, connections, memory regions, IOCs, parent and children.
3. Lexical BM25 ranking over all documents to fill remaining slots.

Only the selected documents are sent to the LLM, keeping prompts small and
every claim traceable to a stored artifact.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

from app.services.ai.evidence import EvidenceCorpus, EvidenceDoc, SEV_RANK, tokenize
from app.services.ioc.patterns import IPV4

INTENTS: dict[str, re.Pattern[str]] = {
    "summary": re.compile(r"summar|overview|what happened|executive|overall|big picture", re.I),
    "most_suspicious": re.compile(r"most suspicious|riskiest|highest risk|top (\d+ )?(suspicious|risk)|which process"
                                  r"(es)? (is|are|look)|rank", re.I),
    "injection": re.compile(r"inject|malfind|shellcode|rwx|reflective|hollow|executable (private )?memory|vad", re.I),
    "parent_child": re.compile(r"parent|child|spawn|process tree|ancestry|launched by", re.I),
    "network": re.compile(r"network|connect|\bip\b|port|c2|command.and.control|remote|beacon|traffic|netscan", re.I),
    "timeline": re.compile(r"timeline|chronolog|sequence of events|order of events|when did", re.I),
    "next_steps": re.compile(r"next step|recommend|additional evidence|what (else )?should|further investigat|"
                             r"examine next|follow.?up", re.I),
    "ioc": re.compile(r"\bioc|indicator|domain|url|hash|artifact", re.I),
    "simple": re.compile(r"simple|plain|layman|non.?technical|explain like|easy", re.I),
    "persistence": re.compile(r"persist|run key|scheduled task|autorun|startup", re.I),
    "credential": re.compile(r"lsass|credential|password|mimikatz|sedebug", re.I),
    "commandline": re.compile(r"command.?line|powershell|encoded|cmd\.exe|script|lolbin", re.I),
    "dll": re.compile(r"\bdll|module|sideload|library", re.I),
}


@dataclass
class Retrieval:
    question: str
    intents: list[str]
    pids: list[int]
    missing_pids: list[int]
    process_names: list[str]
    ips: list[str]
    finding_ids: list[str]
    docs: list[EvidenceDoc] = field(default_factory=list)

    @property
    def ids(self) -> set[str]:
        return {d.id for d in self.docs}

    def evidence_docs(self) -> list[EvidenceDoc]:
        """Retrieved documents other than the always-included analysis summary."""
        return [d for d in self.docs if d.id != "SUMMARY"]


class EvidenceRetriever:
    def __init__(self, corpus: EvidenceCorpus, max_items: int = 40):
        self.corpus = corpus
        self.max_items = max_items
        docs = list(corpus.docs.values())
        self._avgdl = sum(sum(d.tokens.values()) for d in docs) / max(len(docs), 1)
        df: Counter = Counter()
        for d in docs:
            df.update(set(d.tokens))
        n = len(docs)
        self._idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}

    # ---------------------------------------------------------------- entities
    def _entities(self, q: str) -> tuple[list[int], list[int], list[str], list[str], list[str]]:
        explicit = [int(x) for x in re.findall(r"\bpid\s*[:#=]?\s*(\d{1,7})\b", q, re.I)]
        bare = [int(x) for x in re.findall(r"\b(\d{2,7})\b", q) if int(x) in self.corpus.pids]
        pids = list(dict.fromkeys([p for p in explicit + bare if p in self.corpus.pids]))
        missing = [p for p in explicit if p not in self.corpus.pids]
        ql = q.lower()
        names = [n for n in self.corpus.process_names
                 if re.search(r"(?<![\w.])" + re.escape(n) + r"(?![\w])", ql)
                 or (n.endswith(".exe") and len(n) > 7 and re.search(r"\b" + re.escape(n[:-4]) + r"\b", ql))]
        ips = IPV4.findall(q)
        fids = [f"F-{x}" for x in re.findall(r"\b(?:F-|finding\s*#?\s*)(\d+)\b", q, re.I)]
        return pids, missing, names, ips, fids

    # ---------------------------------------------------------------- scoring
    def _bm25(self, query_tokens: list[str], doc: EvidenceDoc, k1: float = 1.4, b: float = 0.75) -> float:
        dl = sum(doc.tokens.values()) or 1
        score = 0.0
        for t in query_tokens:
            tf = doc.tokens.get(t, 0)
            if tf:
                idf = self._idf.get(t, 0.0)
                score += idf * tf * (k1 + 1) / (tf + k1 * (1 - b + b * dl / self._avgdl))
        return score

    def _by_kind(self, kind: str, *, min_sev: str = "info", limit: int = 10,
                 pred=None) -> list[EvidenceDoc]:
        docs = [d for d in self.corpus.docs.values() if d.kind == kind
                and SEV_RANK.get(d.severity, 0) >= SEV_RANK[min_sev] and (pred is None or pred(d))]
        return sorted(docs, key=lambda d: d.rank, reverse=True)[:limit]

    def _for_pid(self, pid: int) -> list[EvidenceDoc]:
        out: list[EvidenceDoc] = []
        proc = self.corpus.process_doc(pid)
        if proc:
            out.append(proc)
            parent_pid = proc.data.get("ppid")
            if parent_pid is not None and self.corpus.process_doc(parent_pid):
                out.append(self.corpus.process_doc(parent_pid))
            for d in self.corpus.docs.values():
                if d.kind == "process" and d.data.get("ppid") == pid and d.id != proc.id:
                    out.append(d)
        out += [self.corpus.docs[i] for i in self.corpus.by_pid.get(pid, []) if i in self.corpus.docs]
        return out

    # ---------------------------------------------------------------- main
    def retrieve(self, question: str) -> Retrieval:
        pids, missing, names, ips, fids = self._entities(question)
        intents = [name for name, rx in INTENTS.items() if rx.search(question)]
        if pids and not intents:
            intents = ["why_pid"]
        elif pids:
            intents.insert(0, "why_pid")
        r = Retrieval(question, intents, pids, missing, names, ips, fids)

        selected: dict[str, EvidenceDoc] = {"SUMMARY": self.corpus.docs["SUMMARY"]}

        def take(docs: list[EvidenceDoc]) -> None:
            for d in docs:
                if d and d.id not in selected:
                    selected[d.id] = d

        for fid in fids:
            if fid in self.corpus.docs:
                f = self.corpus.docs[fid]
                take([f])
                if f.pid is not None:
                    take(self._for_pid(f.pid)[:6])
        for pid in pids:
            take(self._for_pid(pid))
        for name in names:
            for d in self.corpus.docs.values():
                if d.kind == "process" and d.data.get("name", "").lower() == name:
                    take(self._for_pid(d.pid)[:12])
        for ip in ips:
            take([d for d in self.corpus.docs.values() if ip in d.text])

        if "summary" in intents or "most_suspicious" in intents or "simple" in intents:
            take(self._by_kind("process", limit=8, pred=lambda d: d.data.get("risk_score", 0) > 0))
            take(self._by_kind("finding", min_sev="high", limit=12))
        if "injection" in intents:
            take(self._by_kind("finding", limit=12, pred=lambda d: d.data.get("category") == "memory"))
            take(self._by_kind("memory_region", limit=12))
        if "parent_child" in intents:
            take(self._by_kind("finding", limit=12, pred=lambda d: d.data.get("rule_id") == "RULE_SUSPICIOUS_PARENT"))
        if "network" in intents:
            susp_pids = {d.pid for d in self.corpus.docs.values() if d.kind == "process"
                         and d.data.get("risk_score", 0) >= 30}
            take(self._by_kind("network", limit=15, pred=lambda d: d.data.get("suspicious") or d.pid in susp_pids))
            take(self._by_kind("finding", limit=8, pred=lambda d: d.data.get("category") in ("network", "ioc")))
        if "timeline" in intents:
            take(self._by_kind("timeline", limit=25, min_sev="medium"))
        if "ioc" in intents:
            take(self._by_kind("ioc", limit=20, pred=lambda d: d.data.get("confidence") != "low"))
        if "next_steps" in intents:
            take(self._by_kind("finding", min_sev="medium", limit=12))
        if "credential" in intents:
            take(self._by_kind("finding", limit=8, pred=lambda d: d.data.get("category") == "privileges"))
        if "commandline" in intents or "persistence" in intents:
            take(self._by_kind("finding", limit=10, pred=lambda d: d.data.get("category") == "commandline"))
        if "dll" in intents:
            take(self._by_kind("module", limit=12))
            take(self._by_kind("finding", limit=6, pred=lambda d: d.data.get("category") == "modules"))

        # Lexical fill-up
        q_tokens = [t for t in tokenize(question) if len(t) > 2]
        if len(selected) < self.max_items and q_tokens:
            scored = sorted(((self._bm25(q_tokens, d), d) for d in self.corpus.docs.values() if d.id not in selected),
                            key=lambda x: x[0], reverse=True)
            budget = 8 if intents or pids else 15
            take([d for s, d in scored[:budget] if s > 1.5])

        r.docs = list(selected.values())[: self.max_items]
        return r
