"""Behavioural rules: command lines, network connections, privileges, handles, YARA and IOC watchlist."""

from __future__ import annotations

from collections.abc import Iterable

from app.services.detection.base import (
    AnalysisContext,
    DetectionRule,
    Evidence,
    FindingDraft,
    max_severity,
    proc_evidence,
    register,
)
from app.services.detection.cmdline import analyze_cmdline, decode_powershell
from app.services.ioc.patterns import DOMAIN, URL, classify_ip, is_external, is_valid_domain


@register
class SuspiciousCommandLineRule(DetectionRule):
    rule_id = "RULE_SUSPICIOUS_COMMANDLINE"
    title = "Suspicious command line"
    category = "commandline"
    severity = "medium"
    points = 15
    attack = ["T1059"]
    description = ("Matches process command lines (and decoded -EncodedCommand payloads) against documented "
                   "LOLBin, PowerShell and ransomware-preparation patterns in rules/cmdline_patterns.yaml.")
    explanation = {
        "what": "The arguments a program was started with match patterns associated with attacker tradecraft.",
        "why": "Command lines show intent: encoded PowerShell, download cradles and abuse of signed Windows binaries (LOLBins) are documented attacker techniques.",
        "interpretation": "Possible malicious script execution, payload download or defence evasion.",
        "not_prove": "Administrators and software deployment tools use many of the same commands; the context (parent, user, timing) matters.",
        "next_steps": "Review the full and decoded command line, the parent process, and any URLs/IPs referenced; check for follow-on processes and network connections.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        for p in ctx.processes:
            matches, decoded = analyze_cmdline(p.cmdline, ctx.kb)
            if not matches:
                continue
            ev = [Evidence("windows.cmdline", "command_line", "Command line", (p.cmdline or "")[:1000],
                          ref=f"PROC:{p.pid}")]
            for m in matches:
                where = " (in decoded payload)" if m.in_decoded_payload else ""
                ev.append(Evidence("windows.cmdline", "pattern", f"{m.pattern_id}{where}", m.matched))
            if decoded:
                ev.append(Evidence("derived", "decoded_command", "Decoded -EncodedCommand (UTF-16LE)", decoded[:1000]))
            severity = max_severity(*(m.severity for m in matches))
            points = sum(m.points for m in matches)
            conf = 0.85 if decoded and any(m.in_decoded_payload for m in matches) else (
                0.7 if severity in ("high", "critical") else 0.55)
            whys = " ".join(dict.fromkeys(m.why for m in matches))
            attack = sorted({t for m in matches for t in m.attack})
            yield self.make(p, f"{p.label()} command line matched {len(matches)} suspicious pattern(s): "
                               f"{', '.join(m.pattern_id for m in matches)}. {whys}", ev, conf,
                            "Review the decoded command, referenced URLs/IPs, and the parent process; search for "
                            "follow-on processes and network activity.", severity=severity, points=points,
                            attack=attack)


@register
class SuspiciousNetworkRule(DetectionRule):
    rule_id = "RULE_SUSPICIOUS_NETWORK"
    title = "Suspicious network connection"
    category = "network"
    severity = "medium"
    points = 12
    attack = ["T1071", "T1571"]
    required_plugins = ("windows.netscan",)
    description = ("External connections on ports associated with C2/backdoors, from processes that should not "
                   "talk to the network, or listeners on such ports (rules/network.yaml).")
    explanation = {
        "what": "A process has a network connection that does not fit its normal behaviour.",
        "why": "Backdoors and command-and-control implants communicate over the network; connections from processes like rundll32.exe or notepad.exe, or to well-known backdoor ports, are unusual.",
        "interpretation": "Possible command-and-control, data exfiltration or remote access channel.",
        "not_prove": "The remote address is not proven malicious by this analysis; ports and process behaviour are heuristics. Threat-intelligence enrichment is needed to assess the remote host.",
        "next_steps": "Check the remote address against threat intelligence, firewall/proxy/DNS logs and the connection's creation time; look for related IOCs.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        kb = ctx.kb
        for pid, conns in ctx.net_by_pid.items():
            proc = ctx.live_process(pid)
            owner = (proc.name if proc else (conns[0][1].owner or "")).lower()
            ev: list[Evidence] = []
            sev, total = "low", 0
            for idx, c in conns:
                reasons: list[tuple[str, str, int]] = []
                listening = (c.state or "").upper() == "LISTENING"
                if listening and c.local_port in kb.suspicious_ports:
                    reasons.append((f"listening on port {c.local_port} ({kb.suspicious_ports[c.local_port]})",
                                    "medium", 10))
                if not listening and is_external(c.foreign_addr):
                    if c.foreign_port in kb.suspicious_ports:
                        reasons.append((f"remote port {c.foreign_port}: {kb.suspicious_ports[c.foreign_port]}",
                                        "high", 15))
                    if owner in kb.unexpected_network:
                        reasons.append((f"{owner} does not normally make external connections", "medium", 12))
                    elif owner in kb.scripting_network:
                        reasons.append((f"scripting/LOLBin process {owner} connecting externally", "low", 6))
                if not reasons:
                    continue
                ctx.flagged_connections[idx].extend(r[0] for r in reasons)
                ev.append(Evidence("windows.netscan", "network_connection",
                                   "; ".join(r[0] for r in reasons),
                                   f"{c.protocol} {c.local_addr}:{c.local_port} -> {c.foreign_addr}:{c.foreign_port} "
                                   f"{c.state or ''}".strip(), ref=f"NET:{idx}"))
                sev = max_severity(sev, *(r[1] for r in reasons))
                total += max(r[2] for r in reasons)
            if ev:
                label = proc.label() if proc else f"PID {pid}"
                yield self.make(proc, f"{label} has {len(ev)} connection(s) matching network heuristics.", ev,
                                0.6 if sev == "high" else 0.5,
                                "Enrich the remote addresses with threat intelligence and review proxy/DNS/firewall "
                                "logs for the same endpoints.", severity=sev, points=total)


@register
class LsassAccessRule(DetectionRule):
    rule_id = "RULE_LSASS_ACCESS"
    title = "Handle to lsass.exe with memory-read access"
    category = "privileges"
    severity = "high"
    points = 15
    attack = ["T1003.001"]
    required_plugins = ("windows.handles",)
    description = ("A non-allow-listed process holds a process handle to lsass.exe including PROCESS_VM_READ, "
                   "a prerequisite for reading credential material from LSASS memory.")
    explanation = {
        "what": "A program has opened the Windows credential-management process (lsass.exe) with permission to read its memory.",
        "why": "Credential-dumping tools must read lsass.exe memory; very few legitimate programs need this access.",
        "interpretation": "Possible credential-access activity.",
        "not_prove": "Security products, backup and diagnostic tools also open lsass.exe; the handle alone does not show that memory was read or credentials stolen.",
        "next_steps": "Identify the holding process's binary and signer; review authentication logs for subsequent use of accounts that were logged on.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        for pid, handles in ctx.handles_by_pid.items():
            proc = ctx.live_process(pid)
            if ctx.is_trusted(proc, ctx.kb.lsass_allowlist):
                continue
            hits = []
            for h in handles:
                if (h.handle_type or "").lower() != "process" or "lsass.exe" not in (h.name or "").lower():
                    continue
                try:
                    access = int(h.granted_access or "0", 16)
                except ValueError:
                    access = 0
                if access & 0x0010 or access == 0x1FFFFF:
                    hits.append(h)
            if hits:
                ev = [Evidence("windows.handles", "handle", "Process handle to lsass.exe",
                               f"handle {h.handle_value} access {h.granted_access} -> {h.name}") for h in hits[:5]]
                label = proc.label() if proc else f"PID {pid}"
                yield self.make(proc, f"{label} holds {len(hits)} handle(s) to lsass.exe with memory-read access.",
                                ev, 0.7, "Determine what the holding process is and whether it is an approved "
                                         "security/diagnostic tool.")


@register
class DebugPrivilegeRule(DetectionRule):
    rule_id = "RULE_DEBUG_PRIVILEGE"
    title = "SeDebugPrivilege enabled in a non-system process"
    category = "privileges"
    severity = "medium"
    points = 10
    attack = ["T1134"]
    required_plugins = ("windows.privileges",)
    description = "SeDebugPrivilege allows opening any process; it is enabled explicitly by tools that need it."
    explanation = {
        "what": "The process has switched on a privilege that lets it open and manipulate any other process.",
        "why": "Injection and credential-dumping tools enable SeDebugPrivilege; ordinary user applications do not.",
        "interpretation": "The process prepared to access other processes' memory.",
        "not_prove": "Debuggers, administrative and security tools enable this privilege legitimately.",
        "next_steps": "Review the process's handles to other processes and its injection indicators.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        for p in ctx.processes:
            if ctx.is_trusted(p, ctx.kb.debug_allowlist):
                continue
            hit = next((x for x in p.privileges if x["privilege"] == "SeDebugPrivilege" and x["enabled"]), None)
            if hit:
                ev = [proc_evidence(p), Evidence("windows.privileges", "privilege", "SeDebugPrivilege",
                                                 hit["attributes"], ref=f"PROC:{p.pid}")]
                yield self.make(p, f"{p.label()} has SeDebugPrivilege enabled.", ev, 0.6,
                                "Check which processes this process holds handles to.")


@register
class YaraMatchRule(DetectionRule):
    rule_id = "RULE_YARA_MATCH"
    title = "YARA signature match in process memory"
    category = "yara"
    severity = "medium"
    points = 20
    attack = []
    required_plugins = ("windows.vadyarascan",)
    description = "Investigator-supplied YARA rules matched content in process memory (windows.vadyarascan)."
    explanation = {
        "what": "A YARA signature matched bytes inside the process's memory.",
        "why": "YARA rules encode byte/string patterns of known tools or techniques.",
        "interpretation": "The process memory contains content resembling what the rule describes.",
        "not_prove": "YARA matches depend entirely on rule quality; strings may appear in memory for benign reasons (e.g. an AV signature cache, a document being viewed).",
        "next_steps": "Review the rule logic and the matched bytes; corroborate with injection and network indicators.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        for pid, matches in ctx.yara_by_pid.items():
            proc = ctx.live_process(pid)
            sev = max_severity(*(ctx.kb.yara_severity.get(m.rule, "medium") for m in matches))
            ev = [Evidence("windows.vadyarascan", "yara_match", f"Rule {m.rule}",
                           f"offset {m.offset} {m.component or ''} {(m.value or '')[:120]}".strip(),
                           ref=f"YARA:{pid}:{m.offset}") for m in matches[:8]]
            rules = sorted({m.rule for m in matches})
            label = proc.label() if proc else f"PID {pid}"
            yield self.make(proc, f"{len(matches)} YARA match(es) in {label}: {', '.join(rules)}.", ev, 0.65,
                            "Validate the rule and inspect matched content in context.", severity=sev)


@register
class IocWatchlistRule(DetectionRule):
    rule_id = "RULE_IOC_WATCHLIST_MATCH"
    title = "Indicator matches the local threat-intelligence watchlist"
    category = "ioc"
    severity = "high"
    points = 20
    attack = []
    description = "Remote IPs, domains/URLs in command lines and process/module names compared with rules/ioc_watchlist.yaml."
    explanation = {
        "what": "An address, domain or file name in this memory image is on the investigator's watchlist of known-bad indicators.",
        "why": "Watchlists contain indicators from prior incidents or threat intelligence.",
        "interpretation": "Possible link to known malicious infrastructure or tooling, as asserted by the watchlist source.",
        "not_prove": "The finding is only as reliable as the watchlist entry; shared hosting and stale intelligence cause false positives.",
        "next_steps": "Confirm the watchlist entry's provenance and age; search other hosts and logs for the same indicator.",
    }

    def evaluate(self, ctx: AnalysisContext) -> Iterable[FindingDraft]:
        wl = ctx.kb.watchlist
        per_proc: dict[int | None, list[Evidence]] = {}
        for idx, c in enumerate(ctx.evidence.network):
            label = wl.get("ipv4", {}).get((c.foreign_addr or "").lower())
            if label is not None and classify_ip(c.foreign_addr or ""):
                ctx.flagged_connections[idx].append("remote address on IOC watchlist")
                per_proc.setdefault(c.pid, []).append(Evidence(
                    "windows.netscan", "ioc", f"Watchlisted IP ({label})",
                    f"{c.foreign_addr}:{c.foreign_port}", ref=f"NET:{idx}"))
        for p in ctx.processes:
            text = (p.cmdline or "") + "\n" + (decode_powershell(p.cmdline) or "")
            for m in URL.finditer(text):
                host = m.group(0).split("/")[2].split(":")[0].lower()
                if host in wl.get("domain", {}):
                    per_proc.setdefault(p.pid, []).append(Evidence(
                        "windows.cmdline", "ioc", f"Watchlisted domain ({wl['domain'][host]})", m.group(0)))
            for m in DOMAIN.finditer(text):
                d = m.group(1).lower()
                if is_valid_domain(d) and d in wl.get("domain", {}) and not any(d in e.value for e in per_proc.get(p.pid, [])):
                    per_proc.setdefault(p.pid, []).append(Evidence(
                        "windows.cmdline", "ioc", f"Watchlisted domain ({wl['domain'][d]})", d))
            if p.name_lc in wl.get("file_name", {}):
                per_proc.setdefault(p.pid, []).append(Evidence(
                    "windows.pslist", "ioc", f"Watchlisted file name ({wl['file_name'][p.name_lc]})", p.name))
        for pid, ev in per_proc.items():
            proc = ctx.live_process(pid)
            label = proc.label() if proc else f"PID {pid}"
            yield self.make(proc, f"{label} is associated with {len(ev)} watchlisted indicator(s).", ev, 0.85,
                            "Confirm the watchlist entry's source and search for the indicator across the estate.")
