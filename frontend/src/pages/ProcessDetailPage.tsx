import { ArrowDown, ArrowLeft, Bot, ChevronRight, Cpu, EyeOff, FileCode2, Fingerprint, KeyRound, MemoryStick, Network, RefreshCw, ScanSearch, Sparkles, Terminal, XCircle } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { AIMessage } from "../components/forensic/AIMessage";
import { EvidencePanel, FindingCard } from "../components/forensic/cards";
import { useCitationNav } from "../components/forensic/cite";
import { useAnalysis, useAnalysisCrumbs } from "../components/layout/AppLayout";
import { ExplanationPanel } from "../components/process/ExplanationPanel";
import {
  Badge, BAND_COLOR, Button, Card, CopyButton, cx, DataTable, Drawer, EmptyState, ErrorState, KeyValue, Mono, Notice, RiskBadge, Skeleton,
  SkeletonAI, SkeletonCards, Tabs,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { decodePowerShell, fmtTime } from "../services/format";
import type { AIAnswer, Connection, Finding, Module, Process, Region } from "../types";

type Tab = "overview" | "memory" | "modules" | "network" | "cmdline" | "evidence" | "ai";

function ProcChip({ p, jobId, current }: { p: Pick<Process, "pid" | "name" | "risk_score" | "risk_band">; jobId: number; current?: boolean }) {
  const color = p.risk_score > 0 ? BAND_COLOR[p.risk_band] : undefined;
  const body = (
    <span className={cx("flex items-center gap-3 rounded-xl border px-4 py-3 transition-colors", current ? "border-accent bg-accent-soft" : "border-line bg-surface hover:border-line-strong hover:bg-surface-2")}>
      <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: color ?? "var(--color-line-strong)" }} />
      <span className="min-w-0 flex-1 truncate text-sm font-medium text-ink">{p.name}</span>
      <span className="font-mono text-xs tabular text-muted">{p.pid}</span>
      {p.risk_score > 0 && <RiskBadge score={p.risk_score} band={p.risk_band} showBand={false} />}
    </span>
  );
  return current ? body : <Link to={`/analysis/${jobId}/processes/${p.pid}`} className="block rounded-xl">{body}</Link>;
}

function Section({ title, children, subtitle }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <section>
      <h3 className="text-[15px] font-semibold text-ink">{title}</h3>
      {subtitle && <p className="mt-0.5 text-[13px] text-muted">{subtitle}</p>}
      <div className="mt-4">{children}</div>
    </section>
  );
}

export default function ProcessDetailPage() {
  const { jobId } = useAnalysis();
  const pid = Number(useParams().pid);
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as Tab) ?? "overview";
  const setTab = (t: Tab) => setParams(t === "overview" ? {} : { tab: t }, { replace: true });
  const { data, error, loading, reload } = useApi(() => api.process(jobId, pid), [jobId, pid]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [ai, setAi] = useState<AIAnswer | null>(null);
  const [aiErr, setAiErr] = useState<string | null>(null);
  const [aiBusy, setAiBusy] = useState(false);
  const cite = useCitationNav(jobId);
  useAnalysisCrumbs({ label: "Processes", to: `/analysis/${jobId}/processes` }, { label: data ? `${data.process.name} (${pid})` : `PID ${pid}` });

  const askAi = async () => {
    setAiBusy(true);
    setAiErr(null);
    try {
      setAi(await api.aiQuery(jobId, `Why is PID ${pid} suspicious?`));
    } catch (e) {
      setAiErr((e as Error).message);
    } finally {
      setAiBusy(false);
    }
  };
  useEffect(() => {
    if (tab === "ai" && !ai && !aiBusy && !aiErr) askAi();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab]);
  useEffect(() => { setAi(null); setAiErr(null); }, [pid]);

  if (loading && !data) return <><Skeleton className="h-4 w-32" /><Skeleton className="mt-5 h-10 w-80 max-w-full" /><SkeletonCards count={3} className="mt-10 xl:grid-cols-3" /></>;
  if (error || !data) {
    return <ErrorState title={`Process ${pid} unavailable`} message={error ?? "Process not found"} onRetry={reload}
      actions={<Button to={`/analysis/${jobId}/processes`}>All processes</Button>} />;
  }

  const p = data.process;
  const execRegions = data.regions.filter((r) => (r.protection ?? "").includes("EXECUTE"));
  const decoded = decodePowerShell(p.cmdline);
  const cmdFindings = data.findings.filter((f) => f.category === "commandline" || f.evidence.some((e) => e.artifact === "command_line"));
  const regionFinding = (r: Region) => data.findings.find((f) => f.evidence.some((e) => e.ref === `MEM:${r.pid}:${r.start}`));
  const flaggedNet = data.network.filter((c) => c.is_suspicious).length;
  const flaggedMods = data.modules.filter((m) => m.is_suspicious).length;

  return (
    <div>
      <Link to={`/analysis/${jobId}/processes`} className="inline-flex items-center gap-1.5 text-[13px] font-medium text-muted transition-colors hover:text-ink">
        <ArrowLeft className="h-4 w-4" />All processes
      </Link>

      <div className="mt-5 grid gap-6 lg:grid-cols-12">
        <div className="min-w-0 lg:col-span-8">
          <div className="flex flex-wrap items-center gap-3">
            <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-line bg-surface text-ink-2 shadow-card"><Cpu className="h-5 w-5" /></span>
            <div className="min-w-0">
              <h1 className="break-all text-[28px] font-semibold leading-tight tracking-[-0.02em] text-ink md:text-[30px]">{p.name}</h1>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-[13px] text-muted">
                <span className="rounded-md bg-surface-2 px-2 py-0.5 font-mono font-medium text-ink-2 ring-1 ring-line">PID {p.pid}</span>
                <span className="font-mono">PPID {p.ppid ?? "-"}</span>
                {p.is_hidden_candidate && <Badge tone="danger" icon={<EyeOff />}>Not in active process list</Badge>}
                {p.is_terminated && <Badge icon={<XCircle />}>Terminated</Badge>}
                {p.deep_scanned && <Badge tone="accent" icon={<ScanSearch />}>Triaged - deep scanned</Badge>}
              </div>
            </div>
          </div>
          {p.path && <div className="mt-5 flex items-start gap-2 rounded-xl border border-line bg-surface px-4 py-3 shadow-card"><Mono className="flex-1 text-ink">{p.path}</Mono><CopyButton text={p.path} compact /></div>}
        </div>
        <div className="lg:col-span-4">
          <div className="flex h-full flex-col justify-center rounded-2xl border border-line bg-surface p-6 shadow-card">
            <div className="flex items-end justify-between gap-4">
              <div>
                <div className="text-[13px] font-medium text-muted">Risk score</div>
                <div className="mt-1 text-[44px] font-semibold leading-none tracking-[-0.03em] text-ink">{p.risk_score}</div>
              </div>
              <span className="text-sm font-bold uppercase tracking-[0.12em]" style={{ color: p.risk_score ? BAND_COLOR[p.risk_band] : "var(--color-muted)" }}>{p.risk_score ? p.risk_band : "No risk"}</span>
            </div>
            <div className="mt-4 h-2 overflow-hidden rounded-full bg-surface-3">
              <div className="h-full rounded-full" style={{ width: `${Math.max(p.risk_score, 1)}%`, background: p.risk_score ? BAND_COLOR[p.risk_band] : "var(--color-line-strong)" }} />
            </div>
            <div className="mt-3 text-xs text-muted">{data.findings.length} rule{data.findings.length === 1 ? "" : "s"} triggered · prioritisation score, not a verdict</div>
          </div>
        </div>
      </div>

      <div className="mt-10">
        <Tabs value={tab} onChange={setTab} tabs={[
          { key: "overview", label: "Overview", icon: <Cpu /> },
          { key: "memory", label: "Memory", icon: <MemoryStick />, count: execRegions.length },
          { key: "modules", label: "Modules", icon: <FileCode2 />, count: data.modules.length },
          { key: "network", label: "Network", icon: <Network />, count: data.network.length },
          { key: "cmdline", label: "Command Line", icon: <Terminal /> },
          { key: "evidence", label: "Evidence", icon: <Fingerprint />, count: data.findings.length },
          { key: "ai", label: "AI Analysis", icon: <Sparkles /> },
        ]} />
      </div>

      <div key={tab} className="animate-page-in">
        {tab === "overview" && (
          <div className="grid gap-6 lg:grid-cols-12">
            <div className="space-y-6 lg:col-span-7 xl:col-span-8">
              <Card title="Process information">
                <KeyValue cols={2} rows={[
                  ["Creation time (UTC)", fmtTime(p.create_time)],
                  ["Exit time (UTC)", p.exit_time ? fmtTime(p.exit_time) : "Running at acquisition"],
                  ["Threads / handles", `${p.threads ?? "-"} / ${p.handle_count ?? "-"}`],
                  ["Session / WoW64", `${p.session_id ?? "-"} / ${p.wow64 == null ? "-" : p.wow64 ? "Yes" : "No"}`],
                  ["Seen in", <span key="s" className="flex flex-wrap gap-1.5">{(["pslist", "psscan", "pstree"] as const).map((v) => (
                    <Badge key={v} tone={p[`in_${v}`] ? "accent" : "neutral"} className={p[`in_${v}`] ? "" : "line-through opacity-60"}>{v}</Badge>))}</span>],
                  ["EPROCESS offset", p.offset ? <Mono key="o">{p.offset}</Mono> : null],
                  ["Account (SIDs)", data.sids.length ? <span key="sid" className="space-y-0.5">{data.sids.slice(0, 4).map((s) => <span key={s.sid} className="block">{s.name ?? "?"} <Mono className="text-xs text-muted">{s.sid}</Mono></span>)}</span>
                    : p.deep_scanned ? "None recovered" : <span className="text-muted">Not collected (process not triaged)</span>],
                  ["Command line", p.cmdline ? <button key="c" type="button" onClick={() => setTab("cmdline")} className="text-left"><Mono className="line-clamp-2 hover:text-ink">{p.cmdline}</Mono></button>
                    : <span className="text-muted">Not recovered (PEB unavailable or process exited)</span>],
                ]} />
              </Card>
              <Card title="Process lineage" subtitle="Parent and child processes recovered from memory">
                <div className="mx-auto max-w-md">
                  {data.parent ? <ProcChip p={data.parent} jobId={jobId} /> : (
                    <div className="rounded-xl border border-dashed border-line-strong px-4 py-3 text-sm text-muted">Parent PID {p.ppid ?? "?"} not present in memory</div>
                  )}
                  <div className="flex justify-center py-1.5 text-faint"><ArrowDown className="h-4 w-4" /></div>
                  <ProcChip p={p} jobId={jobId} current />
                  {data.children.length > 0 && (
                    <>
                      <div className="flex justify-center py-1.5 text-faint"><ArrowDown className="h-4 w-4" /></div>
                      <div className="space-y-2 border-l-2 border-line pl-4">
                        {data.children.map((c) => <ProcChip key={c.id} p={c} jobId={jobId} />)}
                      </div>
                    </>
                  )}
                </div>
              </Card>
            </div>
            <Card className="lg:col-span-5 xl:col-span-4 lg:self-start" title="Risk contributors" subtitle="points × (0.5 + 0.5 × confidence), capped per category">
              {p.risk_contributors.length === 0 ? <EmptyState compact title="No detection rule fired" /> : (
                <ul className="divide-y divide-line">
                  {p.risk_contributors.map((c, i) => (
                    <li key={i} className="flex gap-4 py-3 first:pt-0 last:pb-0">
                      <span className={cx("w-11 shrink-0 text-right font-mono text-sm font-semibold tabular", c.points > 0 ? "text-sev-high-text" : "text-muted")}>{c.points > 0 ? "+" : ""}{c.points}</span>
                      <span className="min-w-0 text-sm leading-snug text-ink-2">{c.label}
                        {c.confidence != null && <span className="mt-0.5 block text-xs text-muted">{c.base_points} pts × confidence {c.confidence}</span>}
                      </span>
                    </li>
                  ))}
                  <li className="flex gap-4 pt-3 text-sm font-semibold text-ink"><span className="w-11 text-right font-mono tabular">{p.risk_score}</span>Final score</li>
                </ul>
              )}
              <Button className="mt-6 w-full" variant="subtle" icon={<Bot />} onClick={() => setTab("ai")}>Explain with AI</Button>
            </Card>
          </div>
        )}

        {tab === "memory" && (
          <div className="space-y-6">
            <Notice tone="warn">Executable private memory is an <b>indicator</b> of injection, not definitive proof - JIT compilers, security products and packers also create it.</Notice>
            {execRegions.length === 0 ? <Card><EmptyState title="No executable regions recorded" icon={<MemoryStick />}>malfind and vadinfo found no executable regions for this process.</EmptyState></Card>
              : execRegions.map((r) => {
                const f = regionFinding(r);
                return (
                  <EvidencePanel key={r.id} title={`${r.start} – ${r.end}`} severity={f?.severity}
                    eyebrow={<><Badge tone="accent">{r.source.replace("windows.", "")}</Badge>{f ? <span className="font-medium text-ink-2">{f.title}</span> : <span>No rule attributed</span>}</>}
                    actions={f && <Button size="sm" variant="subtle" icon={<Sparkles />} onClick={() => setSelected(f)}>Explain with AI</Button>}>
                    <KeyValue cols={2} rows={[
                      ["Protection", <span key="p" className={cx("font-mono text-[13px]", r.protection?.includes("READWRITE") && "font-semibold text-sev-high-text")}>{r.protection ?? "?"}</span>],
                      ["Private memory", String(r.private_memory ?? "unknown")],
                      ["VAD tag", r.tag ?? "-"],
                      ["PE header", r.has_pe_header ? <span key="pe" className="font-semibold text-sev-high-text">Present (MZ)</span> : "No"],
                      ["Mapped file", r.mapped_file ? <Mono key="m">{r.mapped_file}</Mono> : "None (unbacked)"],
                      ["Commit charge", r.commit_charge ?? "-"],
                    ]} />
                    {(r.hexdump || r.disasm) && (
                      <details className="group mt-6 rounded-xl border border-line">
                        <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-3 text-[13px] font-medium text-ink-2 [&::-webkit-details-marker]:hidden">
                          <ChevronRight className="h-4 w-4 transition-transform group-open:rotate-90" />Raw bytes {r.disasm && "& disassembly"}
                        </summary>
                        {r.hexdump && <pre className="overflow-x-auto border-t border-line bg-page/60 px-4 py-3 font-mono text-xs leading-relaxed text-ink-2">{r.hexdump}</pre>}
                        {r.disasm && <pre className="overflow-x-auto border-t border-line bg-page/60 px-4 py-3 font-mono text-xs leading-relaxed text-muted">{r.disasm}</pre>}
                      </details>
                    )}
                  </EvidencePanel>
                );
              })}
          </div>
        )}

        {tab === "modules" && (
          <Card pad={false}>
            <DataTable<Module> rows={data.modules} rowKey={(m) => m.id} pageSize={30} searchPlaceholder="Search modules..."
              initialSort={{ key: "is_suspicious", dir: "desc" }} empty="No modules recovered."
              rowAccent={(m) => (m.is_suspicious ? "var(--color-sev-high)" : undefined)}
              toolbar={flaggedMods > 0 && <Badge tone="warning">{flaggedMods} flagged</Badge>}
              columns={[
                { key: "name", header: "Module", render: (m) => <span className={m.is_suspicious ? "font-semibold text-ink" : "text-ink-2"}>{m.name}</span> },
                { key: "path", header: "Path", render: (m) => <Mono className="line-clamp-2 max-w-[380px]">{m.path ?? "-"}</Mono> },
                { key: "base", header: "Base", render: (m) => <Mono>{m.base ?? "-"}</Mono> },
                { key: "lists", header: "Loader lists", sortable: false, render: (m) => m.in_load == null ? <span className="text-faint">-</span> : (
                  <span className="flex gap-1">{([["Load", m.in_load], ["Init", m.in_init], ["Mem", m.in_mem]] as const).map(([k, v]) => <Badge key={k} tone={v ? "neutral" : "danger"}>{k} {v ? "✓" : "✗"}</Badge>)}</span>) },
                { key: "is_suspicious", header: "Reason", sortValue: (m) => Number(m.is_suspicious), render: (m) => m.reason ? <span className="text-[13px] text-sev-high-text">{m.reason}</span> : <span className="text-faint">-</span> },
              ]} />
          </Card>
        )}

        {tab === "network" && (
          <Card pad={false}>
            <DataTable<Connection> rows={data.network} rowKey={(c) => c.id} search={data.network.length > 8} empty="No connections owned by this process."
              rowAccent={(c) => (c.is_suspicious ? "var(--color-sev-high)" : undefined)}
              toolbar={flaggedNet > 0 && <Badge tone="warning">{flaggedNet} flagged</Badge>}
              columns={[
                { key: "protocol", header: "Protocol", render: (c) => <span className="font-mono text-[13px]">{c.protocol}</span> },
                { key: "local", header: "Local", sortValue: (c) => `${c.local_addr}:${c.local_port}`, render: (c) => <Mono nowrap>{c.local_addr}:{c.local_port}</Mono> },
                { key: "foreign", header: "Remote", sortValue: (c) => `${c.foreign_addr}:${c.foreign_port}`, render: (c) => <Mono nowrap className={c.is_suspicious ? "font-semibold text-ink" : ""}>{c.foreign_addr}:{c.foreign_port}</Mono> },
                { key: "state", header: "State", render: (c) => c.state ?? "-" },
                { key: "created", header: "Created (UTC)", render: (c) => <span className="whitespace-nowrap text-[13px] text-muted">{fmtTime(c.created)}</span> },
                { key: "reason", header: "Why flagged", render: (c) => c.reason ? <span className="text-[13px] text-sev-high-text">{c.reason}</span> : <span className="text-faint">-</span> },
              ]} />
          </Card>
        )}

        {tab === "cmdline" && (
          <div className="space-y-6">
            <Card title="Command line" subtitle="Recovered from the process environment block (PEB)" actions={p.cmdline && <CopyButton text={p.cmdline} />}>
              {p.cmdline ? <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-xl border border-line bg-page/60 p-5 font-mono text-[13px] leading-relaxed text-ink">{p.cmdline}</pre>
                : <EmptyState compact title="Not recovered" icon={<Terminal />}>The PEB was unavailable or the process had exited.</EmptyState>}
            </Card>
            {decoded && (
              <Card title="Decoded -EncodedCommand payload" subtitle="Base64 (UTF-16LE) decoded for analysis only - shown as text, never executed">
                <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-xl border border-sev-high/25 bg-sev-high/[0.05] p-5 font-mono text-[13px] leading-relaxed text-ink">{decoded}</pre>
              </Card>
            )}
            {data.parent?.cmdline && (
              <Card title={`Parent command line - ${data.parent.name} (${data.parent.pid})`}>
                <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-xl border border-line bg-page/60 p-5 font-mono text-[13px] leading-relaxed text-ink-2">{data.parent.cmdline}</pre>
              </Card>
            )}
            {cmdFindings.length > 0 && (
              <Section title="Command-line findings">
                <div className="grid gap-4 xl:grid-cols-2">{cmdFindings.map((f) => <FindingCard key={f.id} finding={f} jobId={jobId} onOpen={setSelected} />)}</div>
              </Section>
            )}
          </div>
        )}

        {tab === "evidence" && (
          <div className="space-y-10">
            <Section title="Rules triggered" subtitle="Select a finding for its explainable-AI breakdown">
              {data.findings.length === 0 ? <Card><EmptyState compact title="No rules triggered" /></Card> : (
                <div className="grid gap-4 xl:grid-cols-2">{data.findings.map((f) => <FindingCard key={f.id} finding={f} jobId={jobId} onOpen={setSelected} />)}</div>
              )}
            </Section>
            <Section title="Handles, privileges & SIDs" subtitle="Collected only for triaged processes to keep analysis time bounded">
              {!p.deep_scanned ? <Notice>This process was not triaged, so handles, SIDs and privileges were not collected.</Notice> : (
                <div className="space-y-6">
                  {data.privileges.length > 0 && (
                    <Card title="Privileges" icon={<KeyRound />}>
                      <div className="flex flex-wrap gap-2">{data.privileges.map((x) => (
                        <Badge key={x.privilege} tone={x.enabled ? (x.privilege === "SeDebugPrivilege" ? "danger" : "warning") : "neutral"}>{x.privilege}<span className="font-normal opacity-75">{x.enabled ? " enabled" : ""}</span></Badge>
                      ))}</div>
                    </Card>
                  )}
                  {data.handles.length > 0 && (
                    <Card title="Handles of interest" pad={false}>
                      <DataTable rows={data.handles} rowKey={(h) => h.id} search={data.handles.length > 10}
                        columns={[
                          { key: "handle_value", header: "Handle", render: (h) => <Mono>{h.handle_value}</Mono> },
                          { key: "handle_type", header: "Type" },
                          { key: "granted_access", header: "Access", render: (h) => <Mono>{h.granted_access}</Mono> },
                          { key: "name", header: "Object", render: (h) => <Mono className="text-ink">{h.name}</Mono> },
                        ]} />
                    </Card>
                  )}
                </div>
              )}
            </Section>
          </div>
        )}

        {tab === "ai" && (
          <div className="max-w-4xl">
            {aiBusy && !ai ? <Card><SkeletonAI /><p className="mt-5 text-[13px] text-muted">Retrieving evidence for PID {pid} and composing a grounded answer...</p></Card>
              : aiErr ? <ErrorState title="AI analysis failed" message={aiErr} onRetry={askAi} />
                : ai && (
                  <AIMessage content={ai.answer} citations={ai.citations} validation={ai.validation} provider={ai.provider} onCite={(id) => cite(id, ai.citations)}
                    actions={<>
                      <Button size="sm" icon={<Fingerprint />} onClick={() => setTab("evidence")}>View evidence</Button>
                      <Button size="sm" icon={<RefreshCw />} onClick={askAi} disabled={aiBusy}>Regenerate</Button>
                      <Button size="sm" variant="ghost" icon={<Bot />} to={`/analysis/${jobId}/assistant`}>Continue in assistant</Button>
                    </>} />
                )}
          </div>
        )}
      </div>

      <Drawer open={!!selected} onClose={() => setSelected(null)} title={selected?.title} subtitle={selected && `F-${selected.id} · ${selected.rule_id}`}>
        {selected && <ExplanationPanel finding={selected} />}
      </Drawer>
    </div>
  );
}
