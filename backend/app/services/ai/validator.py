"""Response Validator: checks that AI output is supported by the evidence corpus.

Checks performed on every answer (LLM or deterministic):

* every cited evidence ID (``[F-12]``, ``[PROC-4528]`` ...) exists;
* every PID, IPv4 address, hash and ``*.exe``/``*.dll`` name mentioned occurs
  in the investigation's evidence (or the detection knowledge base);
* the answer contains citations unless it states insufficient evidence;
* sentences that assert certainty ("this is malware", "proves") without a
  negation are flagged as over-claiming.

Status: ``grounded`` (all checks pass), ``uncertain`` (warnings only) or
``rejected`` (unsupported entities or unknown citations).
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from app.services.ai.evidence import EvidenceCorpus
from app.services.ioc.patterns import IPV4, MD5, SHA256

INSUFFICIENT = "Insufficient evidence in the analyzed memory image."
CITATION = re.compile(r"\[((?:F|PROC|NET|MEM|MOD|IOC|YARA|TL)-[\w.]+|SUMMARY)\]")
_PID = re.compile(r"\bPID\s*[:#]?\s*(\d{1,7})\b", re.I)
_BINARY = re.compile(r"\b[\w-]+\.(?:exe|dll)\b", re.I)
_OVERCLAIM = re.compile(r"\b(definitely|certainly|undoubtedly|without (a )?doubt|confirmed malware|proves?|proven|"
                        r"is (definitely )?malware|is malicious|guaranteed)\b", re.I)
_NEGATION = re.compile(r"\b(not|no|cannot|can't|doesn't|does not|isn't|without proving|unproven|neither)\b", re.I)


@dataclass
class ValidationReport:
    status: str = "grounded"
    citations: list[str] = field(default_factory=list)
    unknown_citations: list[str] = field(default_factory=list)
    unsupported_entities: list[str] = field(default_factory=list)
    overclaims: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def grounded(self) -> bool:
        return self.status == "grounded"

    def to_dict(self) -> dict:
        return {**asdict(self), "grounded": self.grounded}


class ResponseValidator:
    def __init__(self, corpus: EvidenceCorpus, known_names: set[str] | None = None):
        self.corpus = corpus
        self.known_names = {n.lower() for n in (known_names or set())}

    def validate(self, text: str) -> ValidationReport:
        rep = ValidationReport()
        cited = list(dict.fromkeys(CITATION.findall(text)))
        rep.citations = [c for c in cited if c in self.corpus.docs]
        rep.unknown_citations = [c for c in cited if c not in self.corpus.docs]

        blob = self.corpus.blob
        for pid in {int(p) for p in _PID.findall(text)}:
            if pid not in self.corpus.pids:
                rep.unsupported_entities.append(f"PID {pid}")
        for ip in set(IPV4.findall(text)):
            if ip not in blob:
                rep.unsupported_entities.append(f"IP {ip}")
        for rx in (SHA256, MD5):
            for h in set(rx.findall(text)):
                if h.lower() not in blob:
                    rep.unsupported_entities.append(f"hash {h}")
        for name in {m.lower() for m in _BINARY.findall(text)}:
            if name not in blob and name not in self.known_names:
                rep.unsupported_entities.append(f"binary {name}")

        for sentence in re.split(r"(?<=[.!?])\s+|\n", text):
            if _OVERCLAIM.search(sentence) and not _NEGATION.search(sentence):
                rep.overclaims.append(sentence.strip()[:200])

        insufficient = INSUFFICIENT.lower() in text.lower()
        if not rep.citations and not insufficient:
            rep.warnings.append("Answer contains no evidence citations.")

        if rep.unknown_citations or rep.unsupported_entities:
            rep.status = "rejected"
        elif rep.overclaims or rep.warnings:
            rep.status = "uncertain"
        return rep

    @staticmethod
    def feedback(rep: ValidationReport) -> str:
        parts = []
        if rep.unknown_citations:
            parts.append("These citation IDs do not exist: " + ", ".join(rep.unknown_citations))
        if rep.unsupported_entities:
            parts.append("These entities are not present in the evidence: " + ", ".join(rep.unsupported_entities))
        if rep.overclaims:
            parts.append("Do not state certainty about maliciousness; rephrase: " + " | ".join(rep.overclaims[:3]))
        if rep.warnings:
            parts.append(" ".join(rep.warnings) + " Cite evidence IDs in square brackets.")
        return "Your previous answer failed validation. " + " ".join(parts) + \
            " Rewrite the answer using ONLY the evidence provided, citing IDs."
