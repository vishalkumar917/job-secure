"""Forensic AI Assistant - orchestrates the grounded AI pipeline.

    Evidence Store -> Evidence Retriever -> Prompt Builder -> LLM Provider
                   -> Response Validator -> (regenerate once | mark uncertain | deterministic fallback)

The evidence list and confidence in finding explanations always come from the
database, never from the LLM - the model only writes narrative around them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import AIProviderError
from app.core.logging import get_logger
from app.models import AIAnalysis, AnalysisJob, AppSetting, Finding
from app.services.ai.deterministic import DeterministicEngine
from app.services.ai.evidence import EvidenceCorpus, EvidenceStore
from app.services.ai.prompts import EXPLANATION_KEYS, chat_messages, explanation_messages
from app.services.ai.providers import AIProvider, ChatMessageIn, ProviderConfig, build_provider
from app.services.ai.retriever import EvidenceRetriever
from app.services.ai.validator import INSUFFICIENT, ResponseValidator
from app.services.detection.knowledge import KnowledgeBase, cached_knowledge_base

log = get_logger(__name__)


def resolve_provider_config(db: Session) -> ProviderConfig:
    """Environment defaults, overridden by runtime settings saved from the Settings page (never the API key)."""
    s = get_settings()
    cfg = ProviderConfig(provider=s.ai_provider, base_url=s.ai_base_url, model=s.ai_model,
                         api_key=s.ai_api_key.get_secret_value(), timeout=s.ai_timeout_seconds,
                         temperature=s.ai_temperature)
    row = db.get(AppSetting, "ai")
    if row and row.value:
        for key in ("provider", "base_url", "model", "temperature"):
            if row.value.get(key) not in (None, ""):
                setattr(cfg, key, row.value[key])
    return cfg


def known_names(kb: KnowledgeBase) -> set[str]:
    return (set(kb.system_processes) | kb.shells | kb.document_apps | kb.system_dlls | kb.jit_processes
            | kb.unexpected_network | kb.scripting_network | kb.lsass_allowlist | kb.sensitive_parents)


@dataclass
class AssistantAnswer:
    answer: str
    citations: list[dict[str, Any]]
    validation: dict[str, Any]
    provider: str
    intents: list[str] = field(default_factory=list)
    retrieved: int = 0


class ForensicAssistant:
    def __init__(self, db: Session, job: AnalysisJob, provider: AIProvider | None = None):
        self.db = db
        self.job = job
        settings = get_settings()
        self.kb = cached_knowledge_base(str(settings.rules_dir))
        self.corpus: EvidenceCorpus = EvidenceStore(db).load(job)
        self.validator = ResponseValidator(self.corpus, known_names(self.kb))
        self.engine = DeterministicEngine(self.corpus)
        self.max_items = settings.ai_max_evidence_items
        if provider is None:
            cfg = resolve_provider_config(db)
            provider = build_provider(cfg) if cfg.provider != "deterministic" else None
        self.provider = provider

    @property
    def provider_name(self) -> str:
        return self.provider.name if self.provider else "deterministic"

    def _citations(self, ids: list[str]) -> list[dict[str, Any]]:
        return [{"id": i, "kind": self.corpus.docs[i].kind, "title": self.corpus.docs[i].title,
                 "pid": self.corpus.docs[i].pid} for i in ids if i in self.corpus.docs]

    # ---------------------------------------------------------------- chat
    def ask(self, question: str, history: list[ChatMessageIn] | None = None) -> AssistantAnswer:
        retrieval = EvidenceRetriever(self.corpus, self.max_items).retrieve(question)
        deterministic = self.engine.answer(retrieval)

        if self.provider is None:
            rep = self.validator.validate(deterministic)
            return AssistantAnswer(deterministic, self._citations(rep.citations), rep.to_dict(), "deterministic",
                                   retrieval.intents, len(retrieval.docs))

        try:
            text = self.provider.complete(chat_messages(question, retrieval.docs, history))
            rep = self.validator.validate(text)
            if rep.status == "rejected":
                log.info("ai answer rejected; regenerating", extra={"analysis_id": self.job.id,
                                                                    "unsupported": rep.unsupported_entities})
                text = self.provider.complete(chat_messages(question, retrieval.docs, history,
                                                            ResponseValidator.feedback(rep), text))
                rep = self.validator.validate(text)
            if rep.status == "rejected":
                rep.status = "uncertain"
                rep.warnings.append("Answer still contained unsupported statements after regeneration; they are "
                                    "marked below and must not be relied upon.")
                text += ("\n\n---\n**Validator warning - unverified statements:** "
                         + ", ".join(rep.unsupported_entities + rep.unknown_citations)
                         + ". These items do not appear in the analysed evidence.")
            return AssistantAnswer(text, self._citations(rep.citations), rep.to_dict(), self.provider_name,
                                   retrieval.intents, len(retrieval.docs))
        except AIProviderError as exc:
            log.warning("ai provider failed; using deterministic engine", extra={"analysis_id": self.job.id,
                                                                                  "error": exc.message})
            rep = self.validator.validate(deterministic)
            rep.warnings.append(f"LLM provider unavailable ({exc.message}); deterministic engine used.")
            return AssistantAnswer(deterministic, self._citations(rep.citations), rep.to_dict(),
                                   "deterministic (fallback)", retrieval.intents, len(retrieval.docs))

    # ---------------------------------------------------------------- finding explanation
    def explain_finding(self, finding: Finding, regenerate: bool = False) -> AIAnalysis:
        if not regenerate:
            cached = self.db.scalar(select(AIAnalysis).where(AIAnalysis.finding_id == finding.id,
                                                             AIAnalysis.kind == "finding_explanation")
                                    .order_by(AIAnalysis.id.desc()))
            if cached:
                return cached
        fid = f"F-{finding.id}"
        base = self.engine.explain_finding(fid)
        content, validation, provider = base, {"status": "grounded", "grounded": True}, "deterministic"

        if self.provider is not None:
            doc = self.corpus.docs[fid]
            related = [self.corpus.docs[i] for i in self.corpus.by_pid.get(finding.pid, [])
                       if i != fid and i in self.corpus.docs][:12] if finding.pid is not None else []
            try:
                raw = self.provider.complete(explanation_messages(doc, related), json_mode=True)
                parsed, rep = self._parse_explanation(raw)
                if parsed is None or rep.status == "rejected":
                    fb = ResponseValidator.feedback(rep) if rep else "Return valid JSON with the required keys."
                    raw = self.provider.complete(explanation_messages(doc, related, fb, raw), json_mode=True)
                    parsed, rep = self._parse_explanation(raw)
                if parsed is not None and rep.status != "rejected":
                    content = {**base, **{k: parsed[k] for k in EXPLANATION_KEYS}}
                    validation, provider = rep.to_dict(), self.provider_name
                else:
                    validation = {"status": "grounded", "grounded": True,
                                  "warnings": ["LLM explanation failed validation; deterministic explanation used."]}
            except AIProviderError as exc:
                validation = {"status": "grounded", "grounded": True,
                              "warnings": [f"LLM provider unavailable ({exc.message}); deterministic explanation used."]}
        else:
            text = " ".join(str(base[k]) for k in EXPLANATION_KEYS)
            validation = self.validator.validate(text).to_dict()

        row = AIAnalysis(job_id=self.job.id, finding_id=finding.id, kind="finding_explanation", subject=fid,
                         provider=provider, model=getattr(getattr(self.provider, "config", None), "model", None),
                         content=content, validation=validation, grounded=bool(validation.get("grounded", True)))
        self.db.add(row)
        self.db.commit()
        return row

    def _parse_explanation(self, raw: str):
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            return None, None
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None, None
        if not all(isinstance(data.get(k), str) and data.get(k).strip() for k in EXPLANATION_KEYS):
            return None, None
        rep = self.validator.validate(" ".join(data[k] for k in EXPLANATION_KEYS))
        return data, rep

    # ---------------------------------------------------------------- case summary
    def case_summary(self) -> AIAnalysis:
        text = self.engine.summary_text()
        rep = self.validator.validate(text)
        provider = "deterministic"
        if self.provider is not None:
            retrieval = EvidenceRetriever(self.corpus, self.max_items).retrieve("Summarize the investigation")
            try:
                llm = self.provider.complete(chat_messages(
                    "Write an executive summary of this investigation for a report: overall risk, the most "
                    "suspicious processes and why, key evidence, and limitations.", retrieval.docs))
                llm_rep = self.validator.validate(llm)
                if llm_rep.status != "rejected":
                    text, rep, provider = llm, llm_rep, self.provider_name
            except AIProviderError:
                rep.warnings.append("LLM provider unavailable; deterministic summary used.")
        row = AIAnalysis(job_id=self.job.id, kind="case_summary", subject="SUMMARY", provider=provider,
                         content={"markdown": text}, validation=rep.to_dict(), grounded=rep.grounded or
                         rep.status == "uncertain" and not rep.unsupported_entities)
        self.db.add(row)
        self.db.commit()
        return row


__all__ = ["ForensicAssistant", "AssistantAnswer", "resolve_provider_config", "INSUFFICIENT"]
