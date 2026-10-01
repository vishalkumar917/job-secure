import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAnalysis } from "../components/layout/AppLayout";
import { ProcessTree } from "../components/process/ProcessTree";
import { DataTable } from "../components/ui/DataTable";
import { Card, ErrorState, Loading, Mono, PageHeader, RiskBadge, Tabs } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { fmtTime } from "../services/format";
import type { Process } from "../types";

export default function ProcessesPage() {
  const { jobId } = useAnalysis();
  const nav = useNavigate();
  const [view, setView] = useState<"tree" | "table">("tree");
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const procs = useApi(() => api.processes(jobId), [jobId]);
  const tree = useApi(() => api.tree(jobId), [jobId]);
  const open = (pid: number) => nav(`/analysis/${jobId}/processes/${pid}`);

  const rows = (procs.data ?? []).filter((p) => !suspiciousOnly || p.risk_score >= 30);

  return (
    <>
      <PageHeader title="Processes" subtitle="Merged from pslist (OS view), psscan (pool scan) and pstree. Click a process for full details." />
      <Tabs value={view} onChange={setView} tabs={[{ key: "tree", label: "Process tree" }, { key: "table", label: "Table" }]} />
      {view === "tree" ? (
        <Card>
          {tree.loading && !tree.data ? <Loading /> : tree.error ? <ErrorState message={tree.error} /> :
            <ProcessTree roots={tree.data ?? []} onSelect={(n) => open(n.pid)} />}
        </Card>
      ) : (
        <Card>
          {procs.loading && !procs.data ? <Loading /> : procs.error ? <ErrorState message={procs.error} /> : (
            <DataTable<Process>
              rows={rows} rowKey={(p) => p.id} onRowClick={(p) => open(p.pid)} initialSort={{ key: "risk_score", dir: "desc" }}
              toolbar={<label className="flex items-center gap-2 text-sm text-ink-2"><input type="checkbox" checked={suspiciousOnly} onChange={(e) => setSuspiciousOnly(e.target.checked)} className="accent-[#3987e5]" />Suspicious only (risk &ge; 30)</label>}
              columns={[
                { key: "pid", header: "PID", className: "tabular" },
                { key: "ppid", header: "PPID", className: "tabular" },
                { key: "name", header: "Name", render: (p) => <span className="font-medium text-ink">{p.name}</span> },
                { key: "path", header: "Path / command line", sortValue: (p) => `${p.path ?? ""} ${p.cmdline ?? ""}`,
                  render: (p) => <div className="max-w-xl"><Mono>{p.path ?? "-"}</Mono>{p.cmdline && <div className="mt-0.5 truncate text-xs text-muted" title={p.cmdline}>{p.cmdline}</div>}</div> },
                { key: "create_time", header: "Created (UTC)", render: (p) => <span className="whitespace-nowrap text-xs text-muted">{fmtTime(p.create_time)}</span> },
                { key: "sources", header: "Seen in", sortValue: (p) => Number(p.in_pslist) + Number(p.in_psscan),
                  render: (p) => <div className="flex flex-wrap gap-1 text-[10px]">
                    {p.in_pslist && <span className="rounded bg-surface-3 px-1">pslist</span>}
                    {p.in_psscan && <span className="rounded bg-surface-3 px-1">psscan</span>}
                    {p.is_hidden_candidate && <span className="rounded bg-sev-critical/20 px-1 font-semibold text-[#f08a8a]">hidden?</span>}
                    {p.is_terminated && <span className="rounded bg-surface-3 px-1 text-muted">exited</span>}
                  </div> },
                { key: "risk_score", header: "Risk", render: (p) => <RiskBadge score={p.risk_score} band={p.risk_band} /> },
              ]}
            />
          )}
        </Card>
      )}
    </>
  );
}
