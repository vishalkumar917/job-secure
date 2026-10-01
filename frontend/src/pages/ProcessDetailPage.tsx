import { ArrowLeft, Bot } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useAnalysis } from "../components/layout/AppLayout";
import { ExplanationPanel } from "../components/process/ExplanationPanel";
import { Button, Card, cx, Drawer, EmptyState, ErrorState, KeyValue, Loading, Markdown, Mono, Notice, RiskMeter, SeverityBadge, Tabs } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { confidenceLabel, fmtTime } from "../services/format";
import type { Finding } from "../types";

type Tab = "modules" | "memory" | "network" | "handles" | "evidence";

export default function ProcessDetailPage() {
  const { jobId } = useAnalysis();
  const pid = Number(useParams().pid);
  const { data, error, loading, reload } = useApi(() => api.process(jobId, pid), [jobId, pid]);
  const [tab, setTab] = useState<Tab>("evidence");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [ai, setAi] = useState<string | null>(null);
  const [aiBusy, setAiBusy] = useState(false);

  if (loading && !data) return <Loading />;
  if (error || !data) return <ErrorState message={error ?? "Process not found"} onRetry={reload} />;
  const p = data.process;

  const askAi = async () => {
    setAiBusy(true);
    try {
      setAi((await api.aiQuery(jobId, `Why is PID ${p.pid} suspicious?`)).answer);
    } catch (e) {
      setAi(`Error: ${(e as Error).message}`);
    } finally {
      setAiBusy(false);
    }
  };

  const execRegions = data.regions.filter((r) => (r.protection ?? "").includes("EXECUTE"));
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Link to={`/analysis/${jobId}/processes`} className="inline-flex items-center gap-1 text-sm text-muted hover:text-ink"><ArrowLeft className="h-4 w-4" />Processes</Link>
        <h1 className="text-xl font-semibold text-ink">{p.name} <span className="font-mono text-base text-muted">PID {p.pid}</span></h1>
        {p.is_hidden_candidate && <span className="rounded bg-sev-critical/20 px-2 py-0.5 text-xs font-semibold text-[#f08a8a]">Not in active process list (psscan only)</span>}
        {p.is_terminated && <span className="rounded bg-surface-3 px-2 py-0.5 text-xs text-muted">Terminated</span>}
      </div>

      <div className="grid items-start gap-4 xl:grid-cols-3">
        <Card title="Basic information" className="xl:col-span-2">
          <KeyValue rows={[
            ["PID / PPID", <span key="p" className="tabular">{p.pid} / {p.ppid ?? "-"}</span>],
            ["Name", p.name],
            ["Path", p.path ? <Mono key="pa">{p.path}</Mono> : null],
            ["Command line", p.cmdline ? <Mono key="c">{p.cmdline}</Mono> : <span className="text-muted">not recovered (PEB unavailable or process exited)</span>],
            ["Creation time", fmtTime(p.create_time)],
            ["Exit time", p.exit_time ? fmtTime(p.exit_time) : "-"],
            ["Parent", data.parent ? <Link key="pr" className="text-accent hover:underline" to={`/analysis/${jobId}/processes/${data.parent.pid}`}>{data.parent.name} ({data.parent.pid})</Link> : <span className="text-muted">parent PID {p.ppid} not present in memory</span>],
            ["Children", data.children.length ? <span key="ch" className="flex flex-wrap gap-2">{data.children.map((c) => <Link key={c.id} className="text-accent hover:underline" to={`/analysis/${jobId}/processes/${c.pid}`}>{c.name} ({c.pid})</Link>)}</span> : "none"],
            ["Threads / handles", `${p.threads ?? "-"} / ${p.handle_count ?? "-"}`],
            ["Session / WoW64", `${p.session_id ?? "-"} / ${p.wow64 == null ? "-" : p.wow64 ? "yes" : "no"}`],
            ["Seen in", [p.in_pslist && "pslist", p.in_psscan && "psscan", p.in_pstree && "pstree"].filter(Boolean).join(", ")],
            ["Account (SIDs)", data.sids.length ? data.sids.map((s) => `${s.name ?? "?"} (${s.sid})`).join("; ") : p.deep_scanned ? "none" : "not collected (process not triaged)"],
          ]} />
        </Card>
        <Card title="Risk">
          <RiskMeter score={p.risk_score} band={p.risk_band} />
          <h3 className="mb-2 mt-4 text-xs font-semibold uppercase tracking-wide text-muted">Score contributors</h3>
          {p.risk_contributors.length === 0 ? <p className="text-sm text-muted">No detection rule fired for this process.</p> : (
            <ul className="space-y-1 text-sm">
              {p.risk_contributors.map((c, i) => (
                <li key={i} className="flex gap-2">
                  <span className={cx("w-10 shrink-0 text-right font-mono font-semibold tabular", c.points >= 0 ? "text-sev-high" : "text-muted")}>{c.points > 0 ? "+" : ""}{c.points}</span>
                  <span className="text-ink-2">{c.label}{c.confidence != null && <span className="text-xs text-muted"> ({c.base_points} pts x conf {c.confidence})</span>}</span>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-3 text-xs text-muted">Analytical prioritisation score, not a malware verdict.</p>
          <Button className="mt-3" onClick={askAi} disabled={aiBusy}><Bot className="h-4 w-4" />{aiBusy ? "Asking..." : "AI explanation for this process"}</Button>
        </Card>
      </div>

      {ai && <Card title="AI forensic summary (grounded in evidence)"><Markdown text={ai} /></Card>}

      <Card>
        <Tabs value={tab} onChange={setTab} tabs={[
          { key: "evidence", label: `Rules triggered (${data.findings.length})` },
          { key: "modules", label: `Modules (${data.modules.length})` },
          { key: "memory", label: `Memory (${data.regions.length})` },
          { key: "network", label: `Network (${data.network.length})` },
          { key: "handles", label: `Handles & privileges (${data.handles.length})` },
        ]} />

        {tab === "evidence" && (data.findings.length === 0 ? <EmptyState title="No rules triggered" /> : (
          <div className="space-y-2">
            {data.findings.map((f) => (
              <button key={f.id} onClick={() => setSelected(f)} className="w-full rounded-lg border border-line p-3 text-left hover:border-accent/50 hover:bg-surface-2">
                <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={f.severity} /><span className="font-medium text-ink">{f.title}</span>
                  <span className="ml-auto text-xs text-muted">confidence {confidenceLabel(f.confidence)} ({f.confidence})</span></div>
                <p className="mt-1 text-sm text-ink-2">{f.finding}</p>
                <div className="mt-1 font-mono text-xs text-muted">{f.rule_id} - click for explainable-AI view</div>
              </button>
            ))}
          </div>
        ))}

        {tab === "modules" && (data.modules.length === 0 ? <EmptyState title="No modules recovered" /> : (
          <div className="overflow-x-auto"><table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-muted"><tr><th className="py-1 pr-3">Name</th><th className="pr-3">Path</th><th className="pr-3">Base</th><th className="pr-3">Loader lists</th><th>Flag</th></tr></thead>
            <tbody className="divide-y divide-line">
              {[...data.modules].sort((a, b) => Number(b.is_suspicious) - Number(a.is_suspicious)).map((m) => (
                <tr key={m.id} className={m.is_suspicious ? "bg-sev-high/10" : ""}>
                  <td className="py-1.5 pr-3 font-medium text-ink">{m.name}</td><td className="pr-3"><Mono>{m.path ?? "-"}</Mono></td>
                  <td className="pr-3"><Mono>{m.base ?? "-"}</Mono></td>
                  <td className="pr-3 text-xs">{m.in_load == null ? "-" : `Load:${m.in_load ? "Y" : "N"} Init:${m.in_init ? "Y" : "N"} Mem:${m.in_mem ? "Y" : "N"}`}</td>
                  <td className="text-xs text-sev-high">{m.reason}</td>
                </tr>
              ))}
            </tbody></table></div>
        ))}

        {tab === "memory" && (
          <div className="space-y-3">
            {execRegions.length === 0 ? <EmptyState title="No executable regions recorded for this process" /> : execRegions.map((r) => (
              <div key={r.id} className="rounded-lg border border-line p-3">
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
                  <span className="rounded bg-surface-3 px-1.5 text-xs uppercase">{r.source}</span>
                  <Mono className="text-ink">{r.start} - {r.end}</Mono><span>{r.protection}</span><span className="text-muted">tag {r.tag ?? "?"}</span>
                  <span className="text-muted">private {String(r.private_memory)}</span>
                  {r.has_pe_header && <span className="font-semibold text-sev-high">PE header (MZ)</span>}
                  {r.mapped_file && <Mono>{r.mapped_file}</Mono>}
                </div>
                {r.hexdump && <pre className="mt-2 overflow-x-auto rounded bg-page p-2 font-mono text-xs text-ink-2">{r.hexdump}</pre>}
                {r.disasm && <pre className="mt-1 overflow-x-auto rounded bg-page p-2 font-mono text-xs text-muted">{r.disasm}</pre>}
              </div>
            ))}
            <Notice>Executable private memory is an indicator of injection, not definitive proof.</Notice>
          </div>
        )}

        {tab === "network" && (data.network.length === 0 ? <EmptyState title="No connections owned by this process" /> : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-muted"><tr><th className="py-1 pr-3">Proto</th><th className="pr-3">Local</th><th className="pr-3">Remote</th><th className="pr-3">State</th><th className="pr-3">Created</th><th>Flag</th></tr></thead>
            <tbody className="divide-y divide-line">{data.network.map((c) => (
              <tr key={c.id} className={c.is_suspicious ? "bg-sev-high/10" : ""}>
                <td className="py-1.5 pr-3">{c.protocol}</td><td className="pr-3"><Mono>{c.local_addr}:{c.local_port}</Mono></td>
                <td className="pr-3"><Mono>{c.foreign_addr}:{c.foreign_port}</Mono></td><td className="pr-3">{c.state ?? "-"}</td>
                <td className="pr-3 text-xs text-muted">{fmtTime(c.created)}</td><td className="text-xs text-sev-high">{c.reason}</td>
              </tr>))}
            </tbody>
          </table>
        ))}

        {tab === "handles" && (
          <div className="space-y-4">
            {!p.deep_scanned && <Notice>Handles, SIDs and privileges are collected only for triaged (suspicious) processes to keep analysis time bounded.</Notice>}
            {data.privileges.length > 0 && (
              <div className="flex flex-wrap gap-2">{data.privileges.map((x) => (
                <span key={x.privilege} className={cx("rounded px-2 py-0.5 text-xs", x.enabled ? "bg-sev-medium/15 text-sev-medium" : "bg-surface-3 text-muted")}>{x.privilege} ({x.attributes})</span>
              ))}</div>
            )}
            {data.handles.length > 0 && (
              <table className="w-full text-sm">
                <thead className="text-left text-xs uppercase text-muted"><tr><th className="py-1 pr-3">Handle</th><th className="pr-3">Type</th><th className="pr-3">Access</th><th>Name</th></tr></thead>
                <tbody className="divide-y divide-line">{data.handles.map((h) => (
                  <tr key={h.id}><td className="py-1.5 pr-3"><Mono>{h.handle_value}</Mono></td><td className="pr-3">{h.handle_type}</td><td className="pr-3"><Mono>{h.granted_access}</Mono></td><td><Mono>{h.name}</Mono></td></tr>
                ))}</tbody>
              </table>
            )}
          </div>
        )}
      </Card>

      <Drawer open={!!selected} onClose={() => setSelected(null)} title={selected?.title}>
        {selected && <ExplanationPanel finding={selected} />}
      </Drawer>
    </div>
  );
}
