import { useState } from "react";
import { Link } from "react-router-dom";
import { useAnalysis } from "../components/layout/AppLayout";
import { SEV_COLOR } from "../components/charts";
import { Card, EmptyState, ErrorState, Loading, Notice, PageHeader, SeverityBadge } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { fmtTime } from "../services/format";

export default function TimelinePage() {
  const { jobId } = useAnalysis();
  const { data, error, loading } = useApi(() => api.timeline(jobId), [jobId]);
  const [minSev, setMinSev] = useState("medium");
  const order = ["info", "low", "medium", "high", "critical"];
  const rows = (data ?? []).filter((e) => order.indexOf(e.severity) >= order.indexOf(minSev));
  const dated = rows.filter((r) => r.timestamp);
  const undated = rows.filter((r) => !r.timestamp);

  return (
    <>
      <PageHeader title="Forensic timeline" subtitle="Built only from timestamps present in memory structures (EPROCESS create/exit, TCP endpoint creation, module load time). All times UTC."
        actions={<select className="rounded-lg border border-line bg-surface-2 px-2 py-2 text-sm text-ink" value={minSev} onChange={(e) => setMinSev(e.target.value)} aria-label="Minimum severity">
          <option value="info">All events</option><option value="low">Low and above</option><option value="medium">Medium and above</option><option value="high">High and above</option></select>} />
      <div className="mb-4"><Notice>Findings have no intrinsic timestamp: they are anchored to the owning process's creation time (labelled) or listed as "timestamp unavailable".</Notice></div>
      {loading && !data ? <Loading /> : error ? <ErrorState message={error} /> : rows.length === 0 ? <Card><EmptyState title="No events at this severity" /></Card> : (
        <Card>
          <ol className="relative ml-2 space-y-4 border-l border-line pl-6">
            {dated.map((e) => (
              <li key={e.id}>
                <span className="absolute -left-[6px] mt-1.5 h-3 w-3 rounded-full ring-4 ring-surface" style={{ background: SEV_COLOR[e.severity] }} />
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-mono text-ink-2">{fmtTime(e.timestamp)}</span>
                  <SeverityBadge severity={e.severity} />
                  <span className="rounded bg-surface-3 px-1.5 py-0.5 font-mono text-[11px]">{e.event_type}</span>
                  {e.pid != null && <Link to={`/analysis/${jobId}/processes/${e.pid}`} className="text-accent hover:underline">{e.process_name} ({e.pid})</Link>}
                </div>
                <div className="mt-1 text-sm text-ink-2">{e.description}</div>
                <div className="text-[11px] text-muted">time source: {e.timestamp_source}{e.evidence_ref && ` - evidence ${e.evidence_ref}`}</div>
              </li>
            ))}
          </ol>
          {undated.length > 0 && (
            <div className="mt-6 border-t border-line pt-4">
              <h3 className="mb-2 text-sm font-semibold text-ink-2">Timestamp unavailable</h3>
              <ul className="space-y-2 text-sm">{undated.map((e) => (
                <li key={e.id} className="flex flex-wrap gap-2"><SeverityBadge severity={e.severity} /><span className="text-ink-2">{e.description}</span></li>
              ))}</ul>
            </div>
          )}
        </Card>
      )}
    </>
  );
}
