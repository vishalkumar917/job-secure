import { ArrowRight, CheckCircle2, Circle, Clock, Loader2, ScrollText, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAnalysis, useAnalysisCrumbs } from "../components/layout/AppLayout";
import { Button, Card, cx, DataTable, ErrorState, KeyValue, Mono, Notice, PageHeader, StatusPill } from "../components/ui";
import { useApi, usePolling } from "../hooks/useApi";
import { useNow } from "../hooks/useShell";
import { useToast } from "../hooks/useToast";
import { api } from "../services/api";
import { fmtDuration, fmtElapsed, fmtTime, STAGES } from "../services/format";
import type { PluginRun } from "../types";

export default function AnalysisProgressPage() {
  const { job, jobId, reload } = useAnalysis();
  useAnalysisCrumbs({ label: "Analysis log" });
  const nav = useNavigate();
  const toast = useToast();
  const runs = useApi(() => api.plugins(jobId), [jobId]);
  const status = useApi(() => api.jobStatus(jobId), [jobId]);
  const live = status.data ?? job;
  const active = live.status === "queued" || live.status === "running";
  const now = useNow(1000, active);
  const [retrying, setRetrying] = useState(false);
  usePolling(() => { status.reload(); runs.reload(); }, 1500, active);

  useEffect(() => {
    if (!active && live.status !== job.status) {
      reload();
      if (live.status.startsWith("completed")) toast({ tone: live.status === "completed" ? "success" : "warning", title: "Analysis completed", description: live.status === "completed" ? "All stages finished." : "Some plugins failed - see the log." });
      else if (live.status === "failed") toast({ tone: "error", title: "Analysis failed", description: live.error ?? undefined });
    }
  }, [active, live.status, live.error, job.status, reload, toast]);

  const stageIdx = Math.max(0, STAGES.findIndex((s) => s.key === live.stage));
  const done = live.status.startsWith("completed");
  const failed = live.status === "failed";
  const startMs = live.started_at ? new Date(live.started_at).getTime() : null;
  const endMs = live.completed_at ? new Date(live.completed_at).getTime() : now;
  const elapsed = startMs ? endMs - startMs : 0;
  const state = (i: number) => (done || i < stageIdx ? "done" : i === stageIdx ? (failed ? "failed" : active ? "running" : "pending") : "pending");
  const counts = STAGES.reduce((acc, _, i) => { acc[state(i)]++; return acc; }, { done: 0, running: 0, pending: 0, failed: 0 } as Record<string, number>);

  const retry = async () => {
    setRetrying(true);
    try {
      const j = await api.startAnalysis(job.image_id, job.options?.yara !== false);
      nav(`/analysis/${j.id}/progress`);
    } catch (e) {
      toast({ tone: "error", title: "Could not restart analysis", description: (e as Error).message });
      setRetrying(false);
    }
  };

  return (
    <>
      <PageHeader eyebrow={`Analysis #${job.id}`}
        title={failed ? "Analysis failed" : done ? "Analysis complete" : "Analyzing memory image"}
        subtitle={job.image.original_filename}
        actions={done && <Button variant="primary" to={`/analysis/${jobId}`}>Open analysis summary <ArrowRight /></Button>} />

      {failed && (
        <div className="mb-8">
          <ErrorState title="Volatility could not process this memory image" message={live.error ?? "The analysis stopped before completing."}
            causes={["Unsupported or non-Windows memory image format", "Missing or mismatched Windows symbol tables (ISF)", "Corrupted or truncated image file", "A plugin exceeded its timeout"]}
            onRetry={retrying ? undefined : retry}
            actions={<>
              <Button icon={<ScrollText />} onClick={() => document.getElementById("log")?.scrollIntoView({ behavior: "smooth" })}>View logs</Button>
              <Button variant="ghost" to={`/investigations/${job.case_id}`}>Return to investigation</Button>
            </>} />
        </div>
      )}
      {live.status === "completed_with_errors" && (
        <Notice tone="warn" className="mb-8" title="Completed with plugin errors">Some plugins failed. Their evidence is missing and dependent rules were not evaluated - see the log below and the report's Limitations section.</Notice>
      )}

      <div className="grid gap-6 lg:grid-cols-12">
        <Card className="lg:col-span-8">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <div className="text-[13px] font-medium text-muted">{done ? "Completed" : failed ? "Stopped at" : "Current stage"}</div>
              <div className="mt-1 text-xl font-semibold text-ink">{done ? "All stages finished" : STAGES[stageIdx]?.label}</div>
              {!done && <div className="mt-1 text-sm text-muted">{STAGES[stageIdx]?.detail}</div>}
            </div>
            <div className="text-right">
              <div className="text-[44px] font-semibold leading-none tracking-[-0.03em] tabular text-ink">{live.progress}<span className="text-2xl text-muted">%</span></div>
              <div className="mt-2 inline-flex items-center gap-1.5 text-[13px] tabular text-muted"><Clock className="h-3.5 w-3.5" />{startMs ? fmtElapsed(elapsed) : "waiting"} elapsed</div>
            </div>
          </div>
          <div className="mt-6 h-2.5 overflow-hidden rounded-full bg-surface-3" role="progressbar" aria-valuenow={live.progress} aria-valuemin={0} aria-valuemax={100} aria-label="Analysis progress">
            <div className={cx("relative h-full rounded-full transition-[width] duration-700", failed ? "bg-sev-critical" : done ? "bg-good" : "bg-accent")} style={{ width: `${Math.max(live.progress, 2)}%` }}>
              {active && <span className="skeleton absolute inset-0 !rounded-full !bg-transparent opacity-70" />}
            </div>
          </div>
          <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-[13px] text-muted">
            <span><span className="font-semibold tabular text-ink-2">{counts.done}</span> completed</span>
            {active && <span><span className="font-semibold tabular text-ink-2">{counts.running}</span> running</span>}
            <span><span className="font-semibold tabular text-ink-2">{counts.pending}</span> pending</span>
          </div>

          <ol className="mt-8 grid gap-x-8 sm:grid-cols-2">
            {STAGES.map((s, i) => {
              const st = state(i);
              return (
                <li key={s.key} className="flex gap-3.5 border-t border-line py-3.5">
                  <span className="mt-0.5">
                    {st === "failed" ? <XCircle className="h-[18px] w-[18px] text-sev-critical-text" /> : st === "done" ? <CheckCircle2 className="h-[18px] w-[18px] text-good-text" />
                      : st === "running" ? <Loader2 className="h-[18px] w-[18px] animate-spin text-accent-text" /> : <Circle className="h-[18px] w-[18px] text-line-strong" />}
                  </span>
                  <div className="min-w-0">
                    <div className={cx("text-sm font-medium", st === "pending" ? "text-muted" : "text-ink")}>{s.label}</div>
                    <div className="mt-0.5 text-xs leading-relaxed text-faint">{s.detail}</div>
                  </div>
                </li>
              );
            })}
          </ol>
        </Card>

        <Card className="lg:col-span-4 lg:self-start" title="Run details">
          <KeyValue rows={[
            ["Status", <StatusPill key="s" status={live.status} />],
            ["Started (UTC)", fmtTime(live.started_at)],
            ["Completed (UTC)", live.completed_at ? fmtTime(live.completed_at) : "-"],
            ["Engine", live.volatility_version ?? "-"],
            ["Evidence hash before", live.hash_verified_before == null ? "Pending" : live.hash_verified_before ? <span key="b" className="text-good-text">Verified - matches intake</span> : <span key="b" className="text-sev-critical-text">MISMATCH</span>],
            ["Evidence hash after", live.hash_verified_after == null ? "Pending" : live.hash_verified_after ? <span key="a" className="text-good-text">Verified - unchanged</span> : <span key="a" className="text-sev-critical-text">MISMATCH</span>],
            ["YARA", job.options?.yara === false ? "Disabled" : "Enabled"],
          ]} />
        </Card>
      </div>

      <div id="log" className="scroll-mt-40">
        <Card className="mt-8" pad={false} title="Plugin execution log" subtitle="Every Volatility plugin run with its rationale, arguments, timing, status and output hash">
          {runs.error ? <div className="p-6"><ErrorState compact message={runs.error} onRetry={runs.reload} /></div> : (
            <DataTable<PluginRun>
              rows={runs.data ?? []} loading={runs.loading && !runs.data} rowKey={(r) => r.id} pageSize={20} searchPlaceholder="Filter plugins..."
              empty="No plugin has run yet."
              rowAccent={(r) => (r.status === "failed" || r.status === "timeout" ? "var(--color-sev-critical)" : undefined)}
              columns={[
                { key: "plugin", header: "Plugin", render: (r) => <div className="min-w-[220px]"><Mono className="font-medium text-ink">{r.plugin}</Mono><div className="mt-1 max-w-md text-[13px] leading-snug text-muted">{r.rationale}</div></div> },
                { key: "status", header: "Status", render: (r) => <div><StatusPill status={r.status} />{r.error && <div className="mt-1.5 max-w-xs text-xs leading-snug text-sev-critical-text">{r.error}</div>}</div> },
                { key: "args", header: "Arguments", sortValue: (r) => r.args.join(" "), render: (r) => <Mono>{r.args.join(" ") || "-"}</Mono> },
                { key: "row_count", header: "Rows", align: "right", className: "tabular" },
                { key: "duration_ms", header: "Duration", align: "right", render: (r) => <span className="whitespace-nowrap tabular">{fmtDuration(r.duration_ms)}</span> },
                { key: "output_sha256", header: "Output SHA-256", render: (r) => r.output_sha256 ? <Mono className="text-xs text-muted" title={r.output_sha256}>{r.output_sha256.slice(0, 12)}…</Mono> : <span className="text-faint">-</span> },
              ]}
            />
          )}
        </Card>
      </div>
    </>
  );
}
