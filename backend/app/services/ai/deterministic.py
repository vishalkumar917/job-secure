"""Deterministic explanation engine - the offline fallback for the AI layer.

It composes answers and finding explanations directly from retrieved evidence
documents and the rule explanation templates. It cannot hallucinate: every
sentence is built from stored artifacts and cites their evidence IDs. Its output
passes through the same Response Validator as LLM output.
"""

from __future__ import annotations

from app.services.ai.evidence import SEV_RANK, EvidenceCorpus, EvidenceDoc
from app.services.ai.retriever import Retrieval
from app.services.ai.validator import INSUFFICIENT
from app.services.detection.base import RULE_REGISTRY

LIMITATION = ("These are forensic indicators produced by heuristics and signatures; they support prioritisation "
              "but do not by themselves prove that malware was present.")


def confidence_label(value: float) -> str:
    return "High" if value >= 0.75 else "Medium" if value >= 0.5 else "Low"


def rule_template(rule_id: str) -> dict[str, str]:
    cls = RULE_REGISTRY.get(rule_id)
    return dict(cls.explanation) if cls else {}


class DeterministicEngine:
    def __init__(self, corpus: EvidenceCorpus):
        self.corpus = corpus
        self.summary = corpus.docs["SUMMARY"].data

    # ---------------------------------------------------------------- helpers
    def _docs(self, kind: str, pred=None, limit: int = 50) -> list[EvidenceDoc]:
        docs = [d for d in self.corpus.docs.values() if d.kind == kind and (pred is None or pred(d))]
        return sorted(docs, key=lambda d: d.rank, reverse=True)[:limit]

    def _findings_for(self, pid: int) -> list[EvidenceDoc]:
        return sorted((d for d in self.corpus.docs.values() if d.kind == "finding" and d.pid == pid),
                      key=lambda d: d.rank, reverse=True)

    def _demo_note(self) -> str:
        return ("> **DEMO DATA - NOT REAL FORENSIC EVIDENCE.** This analysis uses the synthetic demonstration "
                "dataset [SUMMARY].\n\n" if self.summary.get("is_demo") else "")

    # ---------------------------------------------------------------- sections
    def explain_process(self, pid: int) -> str:
        proc = self.corpus.process_doc(pid)
        if proc is None:
            return f"No process with the requested PID exists in this analysis. {INSUFFICIENT}"
        d = proc.data
        out = [f"### {d['name']} (PID {pid})",
               f"**Risk score:** {d['risk_score']}/100 ({d['risk_band']}) [{proc.id}] - this is the project's "
               f"analytical prioritisation score, not a malware verdict."]
        findings = self._findings_for(pid)
        if not findings:
            out.append(f"No detection rule fired for {d['name']} (PID {pid}). Based on the analysed evidence it "
                       f"has no suspicious indicators [{proc.id}]. Absence of indicators is not proof of benign "
                       f"behaviour.")
            return "\n\n".join(out)
        contributors = [c for c in d.get("contributors") or []]
        if contributors:
            out.append("**Why it scored this way:**\n" + "\n".join(
                f"- {c['points']:+d} {c['label']}" for c in contributors) + f" [{proc.id}]")
        out.append("**Evidence:**\n" + "\n".join(
            f"{i}. **{f.title}** ({f.severity}, confidence {confidence_label(f.data['confidence'])}): "
            f"{f.data['finding']} [{f.id}]" for i, f in enumerate(findings, 1)))
        parent = d.get("parent")
        parent_doc = self.corpus.process_doc(d["ppid"]) if d.get("ppid") is not None else None
        ctx_lines = []
        if parent and parent_doc:
            ctx_lines.append(f"- Parent: {parent} (PID {d['ppid']}) [{parent_doc.id}]")
        if d.get("path"):
            ctx_lines.append(f"- Image path: `{d['path']}` [{proc.id}]")
        if d.get("cmdline"):
            ctx_lines.append(f"- Command line: `{d['cmdline'][:300]}` [{proc.id}]")
        nets = [n for n in self._docs("network", lambda n: n.pid == pid)]
        for n in nets[:5]:
            ctx_lines.append(f"- Network: {n.data['protocol']} {n.data['local']} -> {n.data['foreign']} "
                             f"{n.data['state'] or ''}{' (flagged: ' + n.data['reason'] + ')' if n.data['suspicious'] else ''} [{n.id}]")
        mems = self._docs("memory_region", lambda m: m.pid == pid and m.data["source"] == "malfind")
        for m in mems[:4]:
            ctx_lines.append(f"- Memory: {m.data['start']}-{m.data['end']} {m.data['protection']}"
                             f"{' with PE header' if m.data['pe'] else ''} [{m.id}]")
        if ctx_lines:
            out.append("**Context:**\n" + "\n".join(ctx_lines))
        interp = list(dict.fromkeys(rule_template(f.data["rule_id"]).get("interpretation", "") for f in findings[:4]))
        out.append("**Possible interpretation:** " + " ".join(i for i in interp if i))
        out.append(f"**Limitations:** {LIMITATION}")
        return "\n\n".join(out)

    def top_processes(self, n: int = 5) -> str:
        procs = self._docs("process", lambda d: d.data["risk_score"] > 0, limit=n)
        if not procs:
            return f"No process triggered any detection rule [SUMMARY]. {INSUFFICIENT} to rank processes as suspicious."
        lines = ["### Most suspicious processes (by analytical risk score)"]
        for i, p in enumerate(procs, 1):
            top = sorted((c for c in p.data.get("contributors") or [] if c.get("rule_id")),
                         key=lambda c: c["points"], reverse=True)[:3]
            reasons = "; ".join(f"{c['points']:+d} {c['label']}" for c in top)
            lines.append(f"{i}. **{p.data['name']}** (PID {p.pid}) - score {p.data['risk_score']} "
                         f"({p.data['risk_band']}): {reasons} [{p.id}]")
        return "\n".join(lines)

    def injection(self) -> str:
        findings = self._docs("finding", lambda f: f.data["category"] == "memory")
        if not findings:
            if "windows.malfind" in (self.summary.get("plugins_available") or []):
                return ("No memory-injection indicators were reported: malfind produced no qualifying regions "
                        "[SUMMARY].")
            return f"{INSUFFICIENT} malfind did not run successfully, so injection could not be assessed [SUMMARY]."
        lines = ["### Evidence suggesting process injection"]
        for f in findings:
            lines.append(f"- **{f.title}** - {f.data['finding']} (confidence "
                         f"{confidence_label(f.data['confidence'])}) [{f.id}]")
            for m in self._docs("memory_region", lambda m, pid=f.pid: m.pid == pid and m.data["source"] == "malfind")[:3]:
                lines.append(f"  - Region {m.data['start']}-{m.data['end']} {m.data['protection']}"
                             f"{', begins with MZ (PE) header' if m.data['pe'] else ''} [{m.id}]")
        lines.append("\n" + rule_template("RULE_EXECUTABLE_PRIVATE_MEMORY").get("not_prove", ""))
        return "\n".join(lines)

    def parent_child(self) -> str:
        findings = self._docs("finding", lambda f: f.data["rule_id"] == "RULE_SUSPICIOUS_PARENT")
        if not findings:
            return "No suspicious parent-child relationships were identified by the rule set [SUMMARY]."
        lines = ["### Suspicious parent-child relationships"]
        for f in findings:
            lines.append(f"- {f.data['finding']} [{f.id}]")
        return "\n".join(lines)

    def network(self) -> str:
        susp = {p.pid for p in self._docs("process", lambda d: d.data["risk_score"] >= 30)}
        conns = self._docs("network", lambda n: n.data["suspicious"] or n.pid in susp)
        if not conns:
            if not self.summary.get("network_connections"):
                return f"{INSUFFICIENT} No network endpoints were recovered from this image [SUMMARY]."
            return "No network connections are flagged or owned by suspicious processes [SUMMARY]."
        lines = ["### Network connections of interest"]
        for n in conns[:15]:
            reason = f" - flagged: {n.data['reason']}" if n.data["suspicious"] else " - owned by a suspicious process"
            lines.append(f"- {n.data['owner']} (PID {n.pid}): {n.data['protocol']} {n.data['local']} -> "
                         f"{n.data['foreign']} {n.data['state'] or ''}{reason} [{n.id}]")
        lines.append("\nRemote addresses are not asserted to be malicious; enrich them with threat intelligence.")
        return "\n".join(lines)

    def timeline(self) -> str:
        events = sorted(self._docs("timeline", limit=200), key=lambda t: t.data["timestamp"])
        procs = sorted(self._docs("process", lambda d: d.data["risk_score"] >= 30),
                       key=lambda d: d.data["create_time"])
        if not events and not procs:
            return f"{INSUFFICIENT} No timestamped suspicious events were recovered [SUMMARY]."
        lines = ["### Incident timeline (timestamps from memory structures, UTC)"]
        for p in procs:
            lines.append(f"- {p.data['create_time']} - {p.data['name']} (PID {p.pid}) created, risk "
                         f"{p.data['risk_score']} [{p.id}]")
        for t in events[:30]:
            lines.append(f"- {t.data['timestamp']} - {t.data['event_type']}: {t.data['description'][:160]} [{t.id}]")
        lines.append("\nFinding events without intrinsic timestamps are anchored to their process creation time "
                     "or marked 'timestamp unavailable'.")
        return "\n".join(lines)

    def iocs(self) -> str:
        items = self._docs("ioc", lambda d: d.data["confidence"] in ("high", "medium"), limit=20)
        if not items:
            return f"{INSUFFICIENT} No medium/high-confidence IOCs were extracted [SUMMARY]."
        lines = ["### Extracted indicators (medium/high confidence)"]
        for i in items:
            lines.append(f"- `{i.data['type']}` **{i.data['value'][:120]}** from {i.data['source']} "
                         f"({i.data['process_name'] or 'n/a'}) - {i.data['confidence']} [{i.id}]")
        return "\n".join(lines)

    def next_steps(self) -> str:
        findings = self._docs("finding", lambda f: SEV_RANK.get(f.severity, 0) >= 2, limit=12)
        if not findings:
            return ("No medium or high severity findings exist [SUMMARY]. Recommended: review the process list "
                    "manually, verify acquisition integrity, and consider running additional plugins.")
        steps: list[str] = []
        for f in findings:
            for s in (rule_template(f.data["rule_id"]).get("next_steps"), f.data.get("recommendation")):
                if s and s not in steps:
                    steps.append(f"{s} [{f.id}]")
        failures = self.summary.get("plugin_failures") or {}
        if failures:
            steps.append(f"Re-run failed plugins ({', '.join(failures)}) after resolving the errors [SUMMARY].")
        not_eval = self.summary.get("rules_not_evaluated") or {}
        if not_eval:
            steps.append(f"Some rules could not be evaluated ({', '.join(list(not_eval)[:5])}); obtain the missing "
                         f"evidence [SUMMARY].")
        steps.append("Correlate with disk, event-log, EDR and network telemetry from the same host and time window.")
        return "### Recommended next investigation steps (defensive)\n" + "\n".join(f"{i}. {s}" for i, s in
                                                                                    enumerate(steps[:12], 1))

    def category(self, categories: set[str], heading: str) -> str:
        findings = self._docs("finding", lambda f: f.data["category"] in categories)
        if not findings:
            return f"No findings in this area ({heading.lower()}) [SUMMARY]."
        return f"### {heading}\n" + "\n".join(f"- {f.data['finding']} [{f.id}]" for f in findings[:10])

    def summary_text(self) -> str:
        s = self.summary
        os_info = s.get("os_info") or {}
        lines = ["### Investigation summary",
                 f"Image **{s.get('image')}** (SHA-256 `{s.get('sha256')}`) was analysed. Operating system: "
                 f"{os_info.get('os_name') or 'unknown'} {os_info.get('architecture') or ''} (identification "
                 f"confidence: {os_info.get('confidence', 'low')}) [SUMMARY].",
                 f"{s.get('total_processes', 0)} processes were reconstructed, of which "
                 f"{s.get('suspicious_processes', 0)} scored 30 or more; {s.get('findings', 0)} findings were raised "
                 f"({s.get('high_severity_findings', 0)} high/critical). Overall analytical risk: "
                 f"**{s.get('overall_risk_score', 0)} ({s.get('overall_risk_band', 'low')})** [SUMMARY]."]
        if s.get("total_processes"):
            lines.append(self.top_processes(3))
        key = self._docs("finding", lambda f: SEV_RANK.get(f.severity, 0) >= 3, limit=6)
        if key:
            lines.append("**Key findings:**\n" + "\n".join(f"- {f.data['finding']} [{f.id}]" for f in key))
        if s.get("plugin_failures"):
            lines.append(f"**Limitations:** plugins that failed: {', '.join(s['plugin_failures'])} [SUMMARY].")
        lines.append(LIMITATION)
        return "\n\n".join(lines)

    def simple(self) -> str:
        top = self._docs("finding", lambda f: SEV_RANK.get(f.severity, 0) >= 2, limit=4)
        if not top:
            return "In plain language: nothing in this memory image triggered our detection rules [SUMMARY]."
        lines = ["### In plain language"]
        for f in top:
            tmpl = rule_template(f.data["rule_id"])
            proc = f.data.get("process_name") or "a process"
            lines.append(f"- **{proc}**: {tmpl.get('what', f.data['finding'])} {tmpl.get('not_prove', '')} [{f.id}]")
        return "\n".join(lines)

    # ---------------------------------------------------------------- dispatcher
    def answer(self, r: Retrieval) -> str:
        parts: list[str] = []
        if r.missing_pids:
            parts.append(f"No process with the requested PID ({', '.join(map(str, r.missing_pids))}) exists in this "
                         f"analysis. {INSUFFICIENT}")
        handled = False
        if r.finding_ids:
            for fid in r.finding_ids:
                if fid in self.corpus.docs:
                    parts.append(self.finding_markdown(fid))
                else:
                    parts.append(f"The requested finding does not exist in this analysis. {INSUFFICIENT}")
            handled = True
        for pid in r.pids:
            parts.append(self.explain_process(pid))
            handled = True
        dispatch = [
            ("summary", self.summary_text), ("most_suspicious", self.top_processes), ("injection", self.injection),
            ("parent_child", self.parent_child), ("network", self.network), ("timeline", self.timeline),
            ("ioc", self.iocs), ("next_steps", self.next_steps),
            ("credential", lambda: self.category({"privileges"}, "Credential-access indicators")),
            ("commandline", lambda: self.category({"commandline"}, "Command-line findings")),
            ("persistence", lambda: self.category({"commandline"}, "Persistence-related command lines")),
            ("dll", lambda: self.category({"modules"}, "Module / DLL findings")),
            ("simple", self.simple),
        ]
        for intent, fn in dispatch:
            if intent in r.intents and not (intent in ("simple",) and handled and r.pids):
                parts.append(fn())
                handled = True
        if not handled and r.evidence_docs():
            parts.append("### Relevant evidence\n" + "\n".join(f"- {d.text[:220]} [{d.id}]"
                                                                for d in r.evidence_docs()[:8]))
            handled = True
        if not handled and not r.missing_pids:
            parts.append(f"{INSUFFICIENT} The question did not match any stored evidence. Try asking about a PID, "
                         f"process name, injection, network activity, IOCs or the timeline.")
        return self._demo_note() + "\n\n".join(p for p in parts if p)

    # ---------------------------------------------------------------- findings
    def explain_finding(self, fid: str) -> dict:
        f = self.corpus.docs[fid]
        tmpl = rule_template(f.data["rule_id"])
        conf = float(f.data["confidence"])
        return {
            "what_happened": f"{tmpl.get('what', '')} In this image: {f.data['finding']} [{fid}]".strip(),
            "why_suspicious": f"{tmpl.get('why', f.data['finding'])} [{fid}]",
            "evidence": f.data.get("evidence") or [],
            "confidence": {"level": confidence_label(conf), "value": round(conf, 2),
                           "basis": "Rule-defined confidence, adjusted for context (e.g. JIT processes, zeroed "
                                    "regions). Confidence expresses evidential strength, not certainty."},
            "possible_interpretation": f"{tmpl.get('interpretation', '')} [{fid}]",
            "does_not_prove": tmpl.get("not_prove", LIMITATION),
            "recommended_next_steps": f"{tmpl.get('next_steps', '')} {f.data.get('recommendation', '')}".strip(),
        }

    def finding_markdown(self, fid: str) -> str:
        e = self.explain_finding(fid)
        ev = "\n".join(f"- {x.get('description')}: `{str(x.get('value'))[:200]}` ({x.get('source')})"
                       for x in e["evidence"][:8])
        return (f"### Finding {fid}\n**What happened?** {e['what_happened']}\n\n"
                f"**Why is it suspicious?** {e['why_suspicious']}\n\n**Evidence:**\n{ev}\n\n"
                f"**Confidence:** {e['confidence']['level']} ({e['confidence']['value']})\n\n"
                f"**Possible interpretation:** {e['possible_interpretation']}\n\n"
                f"**What it does NOT prove:** {e['does_not_prove']}\n\n"
                f"**Recommended next investigation:** {e['recommended_next_steps']}")
