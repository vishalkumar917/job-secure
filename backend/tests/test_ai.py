"""AI layer: evidence retrieval, response validation, deterministic engine and provider fallback."""

from __future__ import annotations

import pytest

from app.core.exceptions import AIProviderError
from app.services.ai.assistant import ForensicAssistant
from app.services.ai.evidence import EvidenceStore
from app.services.ai.providers import AIProvider, ProviderConfig
from app.services.ai.retriever import EvidenceRetriever
from app.services.ai.validator import INSUFFICIENT, ResponseValidator


@pytest.fixture
def db():
    from app.core.database import SessionLocal

    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture
def job(db, demo_job):
    from app.models import AnalysisJob

    return db.get(AnalysisJob, demo_job["id"])


@pytest.fixture
def corpus(db, job):
    return EvidenceStore(db).load(job)


class ScriptedProvider(AIProvider):
    """Test double returning queued responses (or raising)."""

    name = "scripted"

    def __init__(self, responses):
        super().__init__(ProviderConfig("openai", "http://x", "m"))
        self.responses = list(responses)
        self.calls = 0

    def complete(self, messages, *, json_mode=False):
        self.calls += 1
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_retrieval_for_pid_question_pulls_related_evidence(corpus):
    r = EvidenceRetriever(corpus).retrieve("Why is PID 4528 suspicious?")
    assert r.pids == [4528] and "why_pid" in r.intents
    kinds = {d.kind for d in r.docs if d.pid == 4528}
    assert {"process", "finding", "network", "memory_region"} <= kinds
    assert "PROC-4388" in r.ids  # parent included


def test_retrieval_detects_missing_pid(corpus):
    r = EvidenceRetriever(corpus).retrieve("Explain PID 99999")
    assert r.missing_pids == [99999] and r.pids == []


@pytest.mark.parametrize("question,intent", [
    ("What evidence suggests process injection?", "injection"),
    ("Show me suspicious parent-child relationships.", "parent_child"),
    ("What network connections belong to suspicious processes?", "network"),
    ("Generate an incident timeline.", "timeline"),
    ("What additional evidence should an investigator examine?", "next_steps"),
    ("Summarize the investigation.", "summary"),
])
def test_intent_classification(corpus, question, intent):
    assert intent in EvidenceRetriever(corpus).retrieve(question).intents


def test_validator_rejects_hallucinated_entities(corpus):
    v = ResponseValidator(corpus)
    rep = v.validate("PID 31337 connected to 8.8.4.4 and loaded evil.dll [F-999999].")
    assert rep.status == "rejected"
    assert "PID 31337" in rep.unsupported_entities and "IP 8.8.4.4" in rep.unsupported_entities
    assert "binary evil.dll" in rep.unsupported_entities and "F-999999" in rep.unknown_citations


def test_validator_accepts_grounded_text_and_flags_overclaiming(corpus):
    v = ResponseValidator(corpus)
    good = v.validate("svchost.exe (PID 4528) connected to 203.0.113.45 [PROC-4528].")
    assert good.status == "grounded" and good.citations == ["PROC-4528"]
    over = v.validate("PID 4528 is definitely malware [PROC-4528].")
    assert over.status == "uncertain" and over.overclaims
    hedged = v.validate("This does not prove that PID 4528 is malicious [PROC-4528].")
    assert hedged.status == "grounded"


@pytest.mark.parametrize("question", [
    "Which processes are most suspicious?", "Why is PID 4528 suspicious?",
    "What evidence suggests process injection?", "Show me suspicious parent-child relationships.",
    "What network connections belong to suspicious processes?", "Summarize the investigation.",
    "Explain this finding in simple language.", "Generate an incident timeline.",
    "What additional evidence should an investigator examine?",
])
def test_deterministic_answers_are_grounded(db, job, question):
    ans = ForensicAssistant(db, job, provider=None).ask(question)
    assert ans.provider == "deterministic"
    assert ans.validation["status"] in ("grounded", "uncertain"), ans.validation
    assert not ans.validation["unsupported_entities"] and not ans.validation["unknown_citations"]
    assert ans.citations
    assert "DEMO DATA" in ans.answer


def test_insufficient_evidence_message(db, job):
    ans = ForensicAssistant(db, job, provider=None).ask("Tell me about PID 99999")
    assert INSUFFICIENT in ans.answer


def test_llm_hallucination_triggers_regeneration_then_accepts(db, job):
    provider = ScriptedProvider(["PID 31337 is beaconing to 8.8.4.4 [F-1].",
                                 "svchost.exe (PID 4528) has an external connection [PROC-4528]."])
    ans = ForensicAssistant(db, job, provider=provider).ask("Why is PID 4528 suspicious?")
    assert provider.calls == 2 and ans.validation["status"] == "grounded"


def test_persistent_hallucination_is_marked_uncertain(db, job):
    provider = ScriptedProvider(["PID 31337 did it [PROC-4528].", "PID 31337 still did it [PROC-4528]."])
    ans = ForensicAssistant(db, job, provider=provider).ask("Why is PID 4528 suspicious?")
    assert ans.validation["status"] == "uncertain" and "unverified statements" in ans.answer


def test_provider_failure_falls_back_to_deterministic(db, job):
    provider = ScriptedProvider([AIProviderError("connection refused")])
    ans = ForensicAssistant(db, job, provider=provider).ask("Which processes are most suspicious?")
    assert ans.provider == "deterministic (fallback)" and "svchost.exe" in ans.answer


def test_finding_explanation_has_all_sections_and_evidence_from_db(db, job):
    from sqlalchemy import select

    from app.models import Finding

    f = db.scalar(select(Finding).where(Finding.job_id == job.id, Finding.rule_id == "RULE_PE_IN_PRIVATE_MEMORY"))
    row = ForensicAssistant(db, job, provider=None).explain_finding(f, regenerate=True)
    c = row.content
    for key in ("what_happened", "why_suspicious", "evidence", "confidence", "possible_interpretation",
                "does_not_prove", "recommended_next_steps"):
        assert c[key], key
    assert c["evidence"] == f.evidence and c["confidence"]["level"] == "High"
    assert row.grounded


def test_llm_explanation_evidence_cannot_be_overridden(db, job):
    import json

    from sqlalchemy import select

    from app.models import Finding

    f = db.scalar(select(Finding).where(Finding.job_id == job.id, Finding.rule_id == "RULE_MASQUERADING"))
    llm = {"what_happened": f"The process runs from a public folder [F-{f.id}].",
           "why_suspicious": f"System binaries live in System32 [F-{f.id}].",
           "possible_interpretation": f"Possible impostor binary [F-{f.id}].",
           "does_not_prove": "It does not prove the file is malicious.",
           "recommended_next_steps": "Hash the binary and check its signature.",
           "evidence": ["fabricated"]}
    row = ForensicAssistant(db, job, provider=ScriptedProvider([json.dumps(llm)])).explain_finding(f, regenerate=True)
    assert row.provider == "scripted" and row.content["evidence"] == f.evidence
