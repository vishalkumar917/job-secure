import { EyeOff, GitFork, Table2 } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAnalysis, useAnalysisCrumbs } from "../components/layout/AppLayout";
import { ProcessTree } from "../components/process/ProcessTree";
import { Badge, BAND_COLOR, Card, DataTable, ErrorState, Mono, PageHeader, RiskBar, Select, SkeletonTree, Switch, Tabs } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { fmtTime } from "../services/format";
import type { Process } from "../types";

type View = "table" | "tree";

function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="min-w-[120px]">
      <div className="text-[13px] text-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold tracking-[-0.02em] tabular" style={{ color: tone ?? "var(--color-ink)" }}>{value}</div>
    </div>
  );
}

export default function ProcessesPage() {
  const { jobId, job } = useAnalysis();
  useAnalysisCrumbs({ label: "Processes" });
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const view = (params.get("view") as View) ?? "table";
  const [band, setBand] = useState("");
  const [state, setState] = useState("");
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const procs = useApi(() => api.processes(jobId), [jobId]);
  const tree = useApi(() => api.tree(jobId), [jobId]);
  const net = useApi(() => api.network(jobId), [jobId]);
  const findings = useApi(() => api.findings(jobId), [jobId]);
  const open = (pid: number) => nav(`/analysis/${jobId}/processes/${pid}`);

  const netBy = useMemo(() => {
    const m = new Map<number, { total: number; flagged: number }>();
    (net.data ?? []).forEach((c) => {
      if (c.pid == null) return;
      const r = m.get(c.pid) ?? { total: 0, flagged: 0 };
      r.total++;
      if (c.is_suspicious) r.flagged++;
      m.set(c.pid, r);
    });
    return m;
  }, [net.data]);
  const findBy = useMemo(() => {
    const m = new Map<number, number>();
    (findings.data ?? []).forEach((f) => f.process_id != null && m.set(f.process_id, (m.get(f.process_id) ?? 0) + 1));
    return m;
  }, [findings.data]);

  const all = procs.data ?? [];
  const rows = all.filter((p) => (!suspiciousOnly || p.risk_score >= 30)
    && (!band || (band === "none" ? p.risk_score === 0 : p.risk_score > 0 && p.risk_band === band))
    && (!state || (state === "hidden" ? p.is_hidden_candidate : state === "exited" ? p.is_terminated : !p.is_terminated && !p.is_hidden_candidate)));
  const s = job.summary;

  return (
    <>
      <PageHeader title="Process Analysis" subtitle="Merged from pslist (OS view), psscan (pool scan) and pstree. Select a process for its full investigation view." />

      <Card className="mb-8">
        <div className="flex flex-wrap gap-x-12 gap-y-5">
          <Stat label="Total processes" value={s.total_processes ?? all.length} />
          <Stat label="Suspicious (risk ≥ 30)" value={s.suspicious_processes ?? 0} tone={(s.suspicious_processes ?? 0) ? "var(--color-sev-critical-text)" : undefined} />
          <Stat label="Hidden candidates" value={s.hidden_candidates ?? 0} tone={(s.hidden_candidates ?? 0) ? "var(--color-sev-high-text)" : undefined} />
          <Stat label="Terminated" value={s.terminated_processes ?? 0} />
          <Stat label="Triaged (deep scan)" value={all.filter((p) => p.deep_scanned).length} />
        </div>
      </Card>

      <Tabs value={view} onChange={(v) => setParams(v === "table" ? {} : { view: v }, { replace: true })} tabs={[
        { key: "table", label: "Process table", icon: <Table2 />, count: all.length },
        { key: "tree", label: "Process tree", icon: <GitFork /> },
      ]} />

      {view === "tree" ? (
        <Card>
          {tree.loading && !tree.data ? <SkeletonTree /> : tree.error ? <ErrorState compact message={tree.error} onRetry={tree.reload} /> :
            <ProcessTree roots={tree.data ?? []} onSelect={(n) => open(n.pid)} />}
        </Card>
      ) : (
        <Card pad={false}>
          {procs.error ? <div className="p-6"><ErrorState compact message={procs.error} onRetry={procs.reload} /></div> : (
            <DataTable<Process>
              rows={rows} loading={procs.loading && !procs.data} rowKey={(p) => p.id} onRowClick={(p) => open(p.pid)}
              initialSort={{ key: "risk_score", dir: "desc" }} searchPlaceholder="Search name, PID, path, command line..."
              rowAccent={(p) => (p.risk_score > 0 ? BAND_COLOR[p.risk_band] : undefined)}
              empty="No processes match these filters."
              toolbar={<>
                <Select label="Risk band" value={band} onChange={setBand} className="w-40">
                  <option value="">All risk levels</option><option value="critical">Critical</option><option value="high">High</option>
                  <option value="moderate">Moderate</option><option value="low">Low</option><option value="none">No risk</option>
                </Select>
                <Select label="Process state" value={state} onChange={setState} className="w-40">
                  <option value="">Any state</option><option value="active">Active</option><option value="hidden">Hidden candidate</option><option value="exited">Exited</option>
                </Select>
                <Switch checked={suspiciousOnly} onChange={setSuspiciousOnly} label={<span className="text-[13px]">Suspicious only</span>} />
              </>}
              columns={[
                { key: "name", header: "Process", sortValue: (p) => `${p.name} ${p.cmdline ?? ""}`, render: (p) => (
                  <div className="min-w-[180px] max-w-[300px]">
                    <div className={p.risk_score > 0 ? "font-semibold text-ink" : "font-medium text-ink-2"}>{p.name}</div>
                    {p.cmdline && <div className="mt-0.5 truncate font-mono text-xs text-muted" title={p.cmdline}>{p.cmdline}</div>}
                  </div>) },
                { key: "pid", header: "PID", className: "font-mono tabular text-ink" },
                { key: "ppid", header: "PPID", className: "font-mono tabular" },
                { key: "path", header: "Path", render: (p) => p.path ? <Mono className="line-clamp-2 max-w-[320px]" title={p.path}>{p.path}</Mono> : <span className="text-faint">Not recovered</span> },
                { key: "risk_score", header: "Risk", render: (p) => <RiskBar score={p.risk_score} band={p.risk_band} /> },
                { key: "network", header: "Network", sortValue: (p) => netBy.get(p.pid)?.total ?? 0, align: "right", render: (p) => {
                  const n = netBy.get(p.pid);
                  return n ? <span className="tabular">{n.total}{n.flagged > 0 && <span className="ml-1.5 font-semibold text-sev-high-text">({n.flagged} flagged)</span>}</span> : <span className="text-faint">0</span>;
                } },
                { key: "indicators", header: "Indicators", sortValue: (p) => findBy.get(p.id) ?? 0, align: "right", render: (p) => {
                  const n = findBy.get(p.id) ?? 0;
                  return n ? <span className="font-semibold tabular text-ink">{n}</span> : <span className="text-faint">0</span>;
                } },
                { key: "status", header: "Status", sortValue: (p) => (p.is_hidden_candidate ? 2 : p.is_terminated ? 1 : 0), render: (p) => (
                  <div className="flex flex-wrap items-center gap-1.5" title={`Seen in: ${[p.in_pslist && "pslist", p.in_psscan && "psscan", p.in_pstree && "pstree"].filter(Boolean).join(", ")}${p.create_time ? `\nCreated ${fmtTime(p.create_time)}` : ""}`}>
                    {p.is_hidden_candidate ? <Badge tone="danger" icon={<EyeOff />}>Hidden?</Badge> : p.is_terminated ? <Badge>Exited</Badge> : <Badge tone="success">Active</Badge>}
                    {p.deep_scanned && <Badge tone="accent">Triaged</Badge>}
                  </div>) },
              ]}
            />
          )}
        </Card>
      )}
    </>
  );
}
