import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import { useEffect } from "react";
import { Link } from "react-router-dom";
import { useAnalysis } from "../components/layout/AppLayout";
import { DataTable } from "../components/ui/DataTable";
import { Button, Card, ErrorState, Mono, Notice, PageHeader, StatusPill, cx } from "../components/ui";
import { useApi, usePolling } from "../hooks/useApi";
import { api } from "../services/api";
import { fmtDuration, fmtTime, STAGES } from "../services/format";
import type { PluginRun } from "../types";

export default function AnalysisProgressPage() {
  const { job, jobId, reload } = useAnalysis();
  const runs = useApi(() => api.plugins(jobId), [jobId]);
  const status = useApi(() => api.jobStatus(jobId), [jobId]);
  const live = status.data ?? job;
  const active = live.status === "queued" || live.status === "running";
  usePolling(() => { status.reload(); runs.reload(); }, 1500, active);

  useEffect(() => {
    if (!active && live.status !== job.status) reload();
  }, [active, live.status, job.status, reload]);

  const stageIdx = STAGES.findIndex((s) => s.key === live.stage);

  return (
    <>
      <PageHeader title="Analysis progress & log" subtitle="Every Volatility plugin execution is recorded with its rationale, arguments, timing, status and output hash."
        actions={live.status.startsWith("completed") ? <Link to={`/analysis/${jobId}`}><Button variant="primary">Open investigation overview</Button></Link> : undefined} />
      {live.status === "failed" && <div className="mb-4"><ErrorState message={live.error ?? "Analysis failed"} /></div>}
      {live.status === "completed_with_errors" && <div className="mb-4"><Notice tone="warn">Analysis completed, but some plugins failed. Their evidence is missing and dependent rules were not evaluated - see the log below and the report's Limitations section.</Notice></div>}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Pipeline">
          <div className="mb-3 flex items-center justify-between text-sm"><StatusPill status={live.status} /><span className="font-semibold tabular text-ink">{live.progress}%</span></div>
          <div className="mb-4 h-2 overflow-hidden rounded-full bg-surface-3"><div className="h-full bg-accent transition-all" style={{ width: `${live.progress}%` }} /></div>
          <ol className="space-y-1.5 text-sm">
            {STAGES.map((s, i) => {
              const done = live.status.startsWith("completed") || i < stageIdx;
              const current = i === stageIdx && active;
              const failed = live.status === "failed" && i === stageIdx;
              return (
                <li key={s.key} className={cx("flex items-center gap-2", done ? "text-ink-2" : current ? "text-ink" : "text-muted")}>
                  {failed ? <XCircle className="h-4 w-4 text-sev-critical" /> : done ? <CheckCircle2 className="h-4 w-4 text-good" />
                    : current ? <Loader2 className="h-4 w-4 animate-spin text-accent" /> : <Circle className="h-4 w-4" />}
                  {s.label}
                </li>
              );
            })}
          </ol>
          <div className="mt-4 space-y-1 border-t border-line pt-3 text-xs text-muted">
            <div>Started: {fmtTime(live.started_at)}</div>
            <div>Completed: {live.completed_at ? fmtTime(live.completed_at) : "-"}</div>
            <div>Engine: {live.volatility_version ?? "-"}</div>
            <div>Evidence hash verified: before {live.hash_verified_before == null ? "-" : live.hash_verified_before ? "✓" : "✗ MISMATCH"}, after {live.hash_verified_after == null ? "-" : live.hash_verified_after ? "✓" : "✗ MISMATCH"}</div>
          </div>
        </Card>
        <Card title="Plugin execution log" className="lg:col-span-2">
          {runs.error ? <ErrorState message={runs.error} /> : (
            <DataTable<PluginRun>
              rows={runs.data ?? []} rowKey={(r) => r.id} pageSize={30} searchPlaceholder="Filter plugins..."
              empty="No plugin has run yet."
              columns={[
                { key: "plugin", header: "Plugin", render: (r) => <div><Mono className="text-ink">{r.plugin}</Mono><div className="mt-0.5 max-w-md text-xs text-muted">{r.rationale}</div></div> },
                { key: "status", header: "Status", render: (r) => <div><StatusPill status={r.status} />{r.error && <div className="mt-1 max-w-xs text-xs text-[#f08a8a]">{r.error}</div>}</div> },
                { key: "args", header: "Args", sortValue: (r) => r.args.join(" "), render: (r) => <Mono>{r.args.join(" ") || "-"}</Mono> },
                { key: "row_count", header: "Rows", className: "tabular" },
                { key: "duration_ms", header: "Duration", render: (r) => fmtDuration(r.duration_ms) },
              ]}
            />
          )}
        </Card>
      </div>
    </>
  );
}
