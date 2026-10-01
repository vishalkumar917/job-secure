import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useAnalysis } from "../components/layout/AppLayout";
import { ExplanationPanel } from "../components/process/ExplanationPanel";
import { DataTable } from "../components/ui/DataTable";
import { Card, Drawer, ErrorState, Loading, PageHeader, SeverityBadge } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { confidenceLabel } from "../services/format";
import type { Finding } from "../types";

const STATUSES = ["open", "needs_review", "confirmed", "false_positive"];

export default function FindingsPage() {
  const { jobId } = useAnalysis();
  const { data, error, loading, setData } = useApi(() => api.findings(jobId), [jobId]);
  const [sev, setSev] = useState("");
  const [rule, setRule] = useState("");
  const [cat, setCat] = useState("");
  const [proc, setProc] = useState("");
  const [minConf, setMinConf] = useState(0);
  const [open, setOpen] = useState<Finding | null>(null);

  const all = data ?? [];
  const opts = useMemo(() => ({
    rules: [...new Set(all.map((f) => f.rule_id))].sort(),
    cats: [...new Set(all.map((f) => f.category))].sort(),
    procs: [...new Set(all.map((f) => f.process_name).filter(Boolean) as string[])].sort(),
  }), [all]);
  const rows = all.filter((f) => (!sev || f.severity === sev) && (!rule || f.rule_id === rule) && (!cat || f.category === cat)
    && (!proc || f.process_name === proc) && f.confidence >= minConf);

  const setStatus = async (f: Finding, status: string) => {
    const updated = await api.updateFinding(f.id, status);
    setData(all.map((x) => (x.id === f.id ? updated : x)));
  };

  const sel = "rounded-lg border border-line bg-surface-2 px-2 py-2 text-sm text-ink";
  return (
    <>
      <PageHeader title="Findings" subtitle="Output of the modular rule engine. Click a finding for its explainable-AI breakdown. Status changes support investigator triage." />
      <Card>
        {loading && !data ? <Loading /> : error ? <ErrorState message={error} /> : (
          <DataTable<Finding>
            rows={rows} rowKey={(f) => f.id} onRowClick={setOpen} pageSize={30}
            initialSort={{ key: "severity", dir: "asc" }}
            toolbar={<>
              <select className={sel} value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Severity"><option value="">All severities</option>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</select>
              <select className={sel} value={proc} onChange={(e) => setProc(e.target.value)} aria-label="Process"><option value="">All processes</option>{opts.procs.map((p) => <option key={p}>{p}</option>)}</select>
              <select className={sel} value={cat} onChange={(e) => setCat(e.target.value)} aria-label="Finding type"><option value="">All types</option>{opts.cats.map((c) => <option key={c}>{c}</option>)}</select>
              <select className={sel} value={rule} onChange={(e) => setRule(e.target.value)} aria-label="Rule"><option value="">All rules</option>{opts.rules.map((r) => <option key={r}>{r}</option>)}</select>
              <select className={sel} value={minConf} onChange={(e) => setMinConf(Number(e.target.value))} aria-label="Minimum confidence">
                <option value={0}>Any confidence</option><option value={0.5}>Medium+ (&ge;0.5)</option><option value={0.75}>High (&ge;0.75)</option></select>
            </>}
            columns={[
              { key: "severity", header: "Severity", sortValue: (f) => ["critical", "high", "medium", "low", "info"].indexOf(f.severity), render: (f) => <SeverityBadge severity={f.severity} /> },
              { key: "title", header: "Finding", render: (f) => <div className="max-w-lg"><div className="font-medium text-ink">{f.title}</div><div className="line-clamp-2 text-xs text-muted">{f.finding}</div></div> },
              { key: "process_name", header: "Process", render: (f) => f.pid != null ? <Link onClick={(e) => e.stopPropagation()} className="text-accent hover:underline" to={`/analysis/${jobId}/processes/${f.pid}`}>{f.process_name}</Link> : "-" },
              { key: "pid", header: "PID", className: "tabular" },
              { key: "rule_id", header: "Rule", render: (f) => <span className="font-mono text-xs">{f.rule_id}</span> },
              { key: "confidence", header: "Confidence", render: (f) => <span className="tabular">{confidenceLabel(f.confidence)} ({f.confidence})</span> },
              { key: "evidence", header: "Evidence", sortValue: (f) => f.evidence.length, render: (f) => <span className="text-xs text-muted">{f.evidence.length} item(s): {f.evidence[0]?.source}</span> },
              { key: "status", header: "Status", render: (f) => (
                <select value={f.status} onClick={(e) => e.stopPropagation()} onChange={(e) => setStatus(f, e.target.value)}
                  className="rounded border border-line bg-surface-2 px-1 py-0.5 text-xs text-ink" aria-label="Finding status">
                  {STATUSES.map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
                </select>) },
            ]}
          />
        )}
      </Card>
      <Drawer open={!!open} onClose={() => setOpen(null)} title={open && <span>[F-{open.id}] {open.title}</span>}>
        {open && <ExplanationPanel finding={open} />}
      </Drawer>
    </>
  );
}
