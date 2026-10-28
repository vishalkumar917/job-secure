import { Activity, ArrowRight, Cpu, FlaskConical, FolderPlus, Fingerprint, MemoryStick, Network, ShieldAlert, ShieldCheck, Upload } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { SeverityChart } from "../components/charts";
import { FindingCard, MetricCard, RiskCard } from "../components/forensic/cards";
import { Page } from "../components/layout/AppLayout";
import { useCrumbs } from "../components/layout/crumbs";
import { ExplanationPanel } from "../components/process/ExplanationPanel";
import {
  Button, Card, cx, DataTable, DemoTag, Drawer, EmptyState, ErrorState, Notice, PageHeader, RiskBadge, SEV_VAR, sevRank, Skeleton, SkeletonCards,
  SkeletonChart, StatusPill,
} from "../components/ui";
import { useApi, usePolling } from "../hooks/useApi";
import { activeAnalysisStore, useNow } from "../hooks/useShell";
import { useToast } from "../hooks/useToast";
import { api } from "../services/api";
import { fmtRelative, fmtTime, titleCase } from "../services/format";
import type { Dashboard, Finding, SystemStatus } from "../types";

type Recent = Dashboard["recent_analyses"][number];

export default function DashboardPage() {
  useCrumbs([{ label: "Overview" }]);
  const nav = useNavigate();
  const toast = useToast();
  const now = useNow(30000);
  const { data, error, loading, reload } = useApi(() => api.dashboard(), []);
  const status = useApi(() => api.systemStatus(), []);
  const [demoBusy, setDemoBusy] = useState(false);
  const [open, setOpen] = useState<Finding | null>(null);
  usePolling(reload, 4000, (data?.running ?? 0) > 0);

  const latest = data?.recent_analyses.find((a) => a.status.startsWith("completed"));
  const latestJob = useApi(() => (latest ? api.job(latest.id) : Promise.resolve(null)), [latest?.id]);
  const findings = useApi(() => (latest ? api.findings(latest.id) : Promise.resolve([] as Finding[])), [latest?.id]);
  useEffect(() => {
    const j = latestJob.data;
    if (j && !activeAnalysisStore.get()) {
      activeAnalysisStore.set({ id: j.id, case_id: j.case_id, case_number: j.case_number, case_title: j.case_title,
        image: j.image.original_filename, status: j.status, is_demo: j.image.is_demo });
    }
  }, [latestJob.data]);
  const top = [...(findings.data ?? [])].sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || b.confidence - a.confidence).slice(0, 4);

  const loadDemo = async () => {
    setDemoBusy(true);
    try {
      const job = await api.loadDemo();
      toast({ tone: "info", title: "Demo analysis started", description: "Synthetic dataset - not real forensic evidence." });
      nav(`/analysis/${job.id}/progress`);
    } catch (e) {
      toast({ tone: "error", title: "Could not load the demo case", description: (e as Error).message });
      setDemoBusy(false);
    }
  };

  const t = data?.totals ?? {};
  const header = (
    <PageHeader eyebrow="Command center" title="Security Overview"
      meta={data && <>
        <span className="inline-flex items-center gap-1.5"><Activity className="h-3.5 w-3.5" />Last analysis: {data.recent_analyses[0] ? fmtRelative(data.recent_analyses[0].created_at, now) : "none yet"}</span>
        <span>{data.cases} investigation{data.cases === 1 ? "" : "s"} · {data.open_cases} open</span>
        {data.running > 0 && <StatusPill status="running" label={`${data.running} running`} />}
      </>}
      actions={<>
        <Button variant="ghost" onClick={loadDemo} disabled={demoBusy} icon={<FlaskConical />}>{demoBusy ? "Loading demo..." : "Load demo case"}</Button>
        <Button to="/memory-images" icon={<Upload />}>Upload memory image</Button>
        <Button variant="primary" to="/investigations/new" icon={<FolderPlus />}>New investigation</Button>
      </>} />
  );

  if (loading && !data) {
    return (
      <Page>
        {header}
        <SkeletonCards count={6} className="lg:grid-cols-3 2xl:grid-cols-6" />
        <div className="mt-8 grid gap-6 lg:grid-cols-12">
          <Skeleton className="h-[420px] rounded-2xl lg:col-span-4" />
          <Skeleton className="h-[420px] rounded-2xl lg:col-span-8" />
        </div>
      </Page>
    );
  }
  if (error || !data) return <Page>{header}<ErrorState title="Dashboard unavailable" message={error ?? "No data"} onRetry={reload} /></Page>;

  return (
    <Page>
      {header}
      {status.data && !status.data.volatility.available && (
        <Notice tone="warn" className="mb-8" title="Volatility 3 was not found on the server">
          {status.data.volatility.message} Uploaded images cannot be analysed until it is installed - demo mode still works.
        </Notice>
      )}

      {data.recent_analyses.length === 0 ? (
        <Card>
          <EmptyState title="No investigations yet" icon={<FolderPlus />}
            action={<>
              <Button variant="primary" to="/investigations/new" icon={<FolderPlus />}>Create investigation</Button>
              <Button onClick={loadDemo} disabled={demoBusy} icon={<FlaskConical />}>Explore the demo case</Button>
            </>}>
            Create your first forensic investigation by uploading a Windows memory image, or explore the synthetic demo case.
          </EmptyState>
        </Card>
      ) : (
        <>
          <section aria-label="Key metrics" className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6">
            <MetricCard label="Processes" value={t.total_processes ?? 0} icon={<Cpu />} hint="Across latest analyses" />
            <MetricCard label="Suspicious processes" value={t.suspicious_processes ?? 0} icon={<ShieldAlert />} tone={(t.suspicious_processes ?? 0) ? "danger" : undefined} hint="Risk score 30 or higher" />
            <MetricCard label="Memory indicators" value={t.injected_memory_indicators ?? 0} icon={<MemoryStick />} tone={(t.injected_memory_indicators ?? 0) ? "warning" : undefined} hint="Injected / executable private regions" />
            <MetricCard label="Network connections" value={t.network_connections ?? 0} icon={<Network />} hint={`${t.suspicious_connections ?? 0} flagged as suspicious`} />
            <MetricCard label="IOCs" value={t.iocs ?? 0} icon={<Fingerprint />} tone="accent" hint="Extracted indicators" />
            <MetricCard label="Critical findings" value={data.severity_counts.critical ?? 0} icon={<ShieldAlert />} tone={(data.severity_counts.critical ?? 0) ? "danger" : undefined}
              hint={`${t.high_severity_findings ?? 0} high or critical in total`} />
          </section>

          <div className="mt-8 grid gap-6 lg:grid-cols-12">
            <div className="lg:col-span-5 xl:col-span-4">
              {latest && latest.risk_band && latest.risk_score != null ? (
                <RiskCard className="h-full" score={latest.risk_score} band={latest.risk_band} findings={latestJob.data?.summary.findings}
                  footer={<>Latest analysis: <Link className="font-medium text-ink-2 hover:text-accent-text" to={`/analysis/${latest.id}`}>{latest.case_number} · #{latest.id}</Link>. A prioritisation score, not a malware verdict.</>}>
                  {latestJob.data?.summary.severity_counts && <SeverityBreakdown counts={latestJob.data.summary.severity_counts} />}
                  <Button className="mt-6" to={`/analysis/${latest.id}`} icon={<ArrowRight />}>Open analysis</Button>
                </RiskCard>
              ) : <Card title="Overall investigation risk"><EmptyState compact title="No completed analysis yet" /></Card>}
            </div>
            <Card className="lg:col-span-7 xl:col-span-8" title="Recent findings"
              subtitle={latest ? `Highest-severity findings from ${latest.case_number} · analysis #${latest.id}` : undefined}
              actions={latest && <Button size="sm" variant="ghost" to={`/analysis/${latest.id}/findings`}>View all findings <ArrowRight /></Button>}>
              {findings.loading && !findings.data ? (
                <div className="grid gap-4 xl:grid-cols-2">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-44 rounded-xl" />)}</div>
              ) : top.length === 0 ? (
                <EmptyState compact icon={<ShieldCheck />} title="No findings">No detection rule fired in the latest analysis.</EmptyState>
              ) : (
                <div className="grid gap-4 xl:grid-cols-2">
                  {top.map((f) => <FindingCard key={f.id} finding={f} jobId={latest!.id} onOpen={setOpen} compact />)}
                </div>
              )}
            </Card>
          </div>

          <div className="mt-8 grid gap-6 lg:grid-cols-12">
            <Card className="lg:col-span-7 xl:col-span-8" title="Recent analyses" pad={false}
              actions={<Button size="sm" variant="ghost" to="/investigations">All investigations <ArrowRight /></Button>}>
              <DataTable<Recent> rows={data.recent_analyses} rowKey={(a) => a.id} search={false} pageSize={6}
                onRowClick={(a) => nav(a.status.startsWith("completed") ? `/analysis/${a.id}` : `/analysis/${a.id}/progress`)}
                columns={[
                  { key: "case_number", header: "Investigation", render: (a) => (
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 font-medium text-ink">{a.case_number}{a.is_demo && <DemoTag />}</div>
                      <div className="mt-0.5 max-w-[280px] truncate text-[13px] text-muted">{a.image}</div>
                    </div>) },
                  { key: "status", header: "Status", render: (a) => <span className="inline-flex items-center gap-2"><StatusPill status={a.status} />{a.status === "running" && <span className="text-xs tabular text-muted">{a.progress}%</span>}</span> },
                  { key: "risk_score", header: "Risk", render: (a) => <RiskBadge score={a.risk_score} band={a.risk_band} /> },
                  { key: "created_at", header: "Started", render: (a) => <span className="whitespace-nowrap text-[13px] text-muted" title={fmtTime(a.created_at)}>{fmtRelative(a.created_at, now)}</span> },
                ]} />
            </Card>
            <PlatformStatus status={status.data} />
          </div>

          <div className="mt-8 grid gap-6 lg:grid-cols-12">
            <Card className="lg:col-span-7 xl:col-span-8" title="Chain-of-custody activity" subtitle="Every evidence action is recorded with actor and time">
              {data.recent_custody.length === 0 ? <EmptyState compact title="No events yet" /> : (
                <ol className="relative space-y-6 pl-6 before:absolute before:bottom-2 before:left-[5px] before:top-2 before:w-px before:bg-line">
                  {data.recent_custody.slice(0, 7).map((c, i) => (
                    <li key={i} className="relative">
                      <span className={cx("absolute -left-6 top-1.5 h-[11px] w-[11px] rounded-full border-2 border-surface", i === 0 ? "bg-accent" : "bg-line-strong")} />
                      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
                        <span className="text-sm font-medium text-ink">{titleCase(c.action)} <span className="font-normal text-muted">by {c.actor}</span></span>
                        <span className="text-xs text-muted" title={fmtTime(c.timestamp)}>{fmtRelative(c.timestamp, now)}</span>
                      </div>
                      {c.details && <p className="mt-1 truncate text-[13px] text-muted">{c.details}</p>}
                    </li>
                  ))}
                </ol>
              )}
            </Card>
            <Card className="lg:col-span-5 xl:col-span-4" title="Findings across analyses" subtitle="Latest completed analysis per image">
              <SeverityChart counts={data.severity_counts} height={250} />
            </Card>
          </div>
        </>
      )}

      <Drawer open={!!open} onClose={() => setOpen(null)} title={open?.title} subtitle={open && `F-${open.id} · ${open.rule_id}`}
        footer={open && latest && <Button variant="primary" to={`/analysis/${latest.id}/findings?f=${open.id}`}>Open in findings</Button>}>
        {open && <ExplanationPanel finding={open} />}
      </Drawer>
    </Page>
  );
}

function SeverityBreakdown({ counts }: { counts: Partial<Record<string, number>> }) {
  const rows = (["critical", "high", "medium", "low"] as const).map((k) => [k, counts[k] ?? 0] as const);
  const total = Math.max(1, rows.reduce((a, [, n]) => a + n, 0));
  return (
    <ul className="mt-6 space-y-3 border-t border-line pt-5">
      {rows.map(([k, n]) => (
        <li key={k} className="grid grid-cols-[84px_1fr_28px] items-center gap-3 text-[13px]">
          <span className="flex items-center gap-2 capitalize text-ink-2"><span className="h-2 w-2 rounded-full" style={{ background: SEV_VAR[k] }} />{k}</span>
          <span className="h-1.5 overflow-hidden rounded-full bg-surface-3"><span className="block h-full rounded-full" style={{ width: `${(n / total) * 100}%`, background: SEV_VAR[k] }} /></span>
          <span className="text-right font-semibold tabular text-ink">{n}</span>
        </li>
      ))}
    </ul>
  );
}

function PlatformStatus({ status }: { status?: SystemStatus }) {
  return (
    <Card className="lg:col-span-5 xl:col-span-4" title="Platform status">
      {status ? (
        <ul className="divide-y divide-line">
          <StatusRow label="Volatility 3" ok={status.volatility.available} value={status.volatility.available ? `v${status.volatility.version ?? "?"}` : "Not installed"} />
          <StatusRow label="YARA" ok={status.yara_python} value={status.yara_python ? "yara-python" : "Volatility backend"} neutral={!status.yara_python} />
          <StatusRow label="AI provider" ok value={status.ai.provider + (status.ai.model ? ` · ${status.ai.model}` : "")} />
          <StatusRow label="Formats" ok value={status.limits.allowed_extensions.join(" ")} neutral />
          <StatusRow label="Plugin timeout" ok value={`${status.limits.plugin_timeout_seconds}s`} neutral />
        </ul>
      ) : <SkeletonChart height={160} />}
    </Card>
  );
}

function StatusRow({ label, value, ok, neutral }: { label: string; value: string; ok: boolean; neutral?: boolean }) {
  return (
    <li className="flex items-center justify-between gap-4 py-3.5 first:pt-0 last:pb-0">
      <span className="flex shrink-0 items-center gap-2.5 text-sm text-ink-2">
        <span className={cx("h-2 w-2 rounded-full", neutral ? "bg-line-strong" : ok ? "bg-good" : "bg-sev-high")} />{label}
      </span>
      <span className="min-w-0 break-words text-right text-sm font-medium text-ink">{value}</span>
    </li>
  );
}
