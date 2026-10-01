"""Prompt Builder: assembles grounded prompts from retrieved evidence documents."""

from __future__ import annotations

import json

from app.services.ai.evidence import EvidenceDoc
from app.services.ai.providers import ChatMessageIn
from app.services.ai.validator import INSUFFICIENT

SYSTEM_PROMPT = f"""You are a digital-forensics analysis assistant working on a Windows memory-forensics case.
You are given EVIDENCE documents extracted by Volatility 3 and a rule-based detection engine.

Rules you must follow:
1. Use ONLY the evidence provided. Never invent processes, PIDs, IP addresses, hashes, file names or events.
2. Cite the evidence ID in square brackets after every factual statement, e.g. "PID 4528 has RWX memory [F-12]".
3. If the evidence does not answer the question, say exactly: "{INSUFFICIENT}" and state what is missing.
4. Clearly separate evidence (what was observed) from interpretation (what it might mean).
5. Never claim something IS malware or that evidence PROVES compromise. Use language such as "indicates",
   "is consistent with", "suggests". Indicators are not verdicts.
6. The risk score is this project's analytical prioritisation model, not an authoritative verdict.
7. Recommend only defensive, investigative next steps.
8. If the SUMMARY says the data is synthetic demo data, mention that the findings are from demo data."""


def render_evidence(docs: list[EvidenceDoc]) -> str:
    lines = []
    for d in docs:
        lines.append(f"[{d.id}] ({d.kind}{', ' + d.severity if d.severity != 'info' else ''}) {d.text}")
    return "\n".join(lines)


def chat_messages(question: str, docs: list[EvidenceDoc], history: list[ChatMessageIn] | None = None,
                  feedback: str | None = None, previous: str | None = None) -> list[ChatMessageIn]:
    msgs = [ChatMessageIn("system", SYSTEM_PROMPT)]
    for h in (history or [])[-4:]:
        msgs.append(h)
    msgs.append(ChatMessageIn("user", f"EVIDENCE:\n{render_evidence(docs)}\n\nQUESTION: {question}\n\n"
                                      "Answer in concise Markdown with citations."))
    if feedback and previous:
        msgs.append(ChatMessageIn("assistant", previous))
        msgs.append(ChatMessageIn("user", feedback))
    return msgs


EXPLANATION_KEYS = ["what_happened", "why_suspicious", "possible_interpretation", "does_not_prove",
                    "recommended_next_steps"]


def explanation_messages(finding: EvidenceDoc, related: list[EvidenceDoc],
                         feedback: str | None = None, previous: str | None = None) -> list[ChatMessageIn]:
    schema = {k: "string (plain language, cite evidence IDs in [brackets])" for k in EXPLANATION_KEYS}
    user = (f"EVIDENCE:\n{render_evidence([finding, *related])}\n\n"
            f"Explain finding [{finding.id}] for an investigator. Respond with a JSON object with exactly these keys: "
            f"{json.dumps(schema)}. 'does_not_prove' must state the forensic limitation. "
            f"'recommended_next_steps' must be safe, defensive investigation steps.")
    msgs = [ChatMessageIn("system", SYSTEM_PROMPT), ChatMessageIn("user", user)]
    if feedback and previous:
        msgs += [ChatMessageIn("assistant", previous), ChatMessageIn("user", feedback + " Respond with JSON only.")]
    return msgs
