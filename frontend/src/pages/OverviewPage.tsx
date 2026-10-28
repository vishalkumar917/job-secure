import { ArrowRight, Bot, Cpu, Fingerprint, MemoryStick, Network, ShieldAlert, Sparkles } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { CategoryChart, NetworkChart, ProcessTimelineChart, SeverityChart, TopRiskChart } from "../components/charts";
import { ValidationBadge } from "../components/forensic/AIMessage";
import { MetricCard, RiskCard } from "../components/forensic/cards";
import { useCitationNav } from "../components/forensic/cite";
import { useAnalysis, useAnalysisCrumbs } from "../components/layout/AppLayout";
import { Button, Card, CopyButton, ErrorState, KeyValue, Markdown, Mono, Notice, PageHeader, SkeletonAI, SkeletonChart } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { fmtBytes, fmtTime } from "../services/format";

export default function OverviewPage() {
  const { job, jobId } = useAnalysis();
  useAnalysisCrumbs();
  const nav = useNavigate();
  const cite = useCitationNav(jobId);
  const procs = useApi(() => api.processes(jobId), [jobId]);
  const net = useApi(() => api.network(jobId), [jobId]);
  const summaryAi = useApi(() => api.aiSummary(jobId), [jobId]);
  const s = job.summary;
  const os = job.image.os_info ?? {};
  const goProc = (pid: number) => nav(`/analysis/${jobId}/processes/${pid}`);
  const base = `/analysis/${jobId}`;
  const failures = Object.keys(s.plugin_failures ?? {});

  return (
    <>
      <PageHeader eyebrow="Analysis summary" title={job.case_title}
        subtitle={[os.os_name ? `${os.os_name} ${os.architecture ?? ""}`.trim() : "Operating system not identified", `${s.total_processes ?? 0} processes analysed`, `completed ${fmtTime(job.completed_at)}`].join(" · ")}
        actions={<>
          <Button to={`${base}/findings`} icon={<ShieldAlert />}>Review findings</Button>
          <Button variant="primary" to={`${base}/reports`}>Generate report <ArrowRight /></Button>
        </>} />

      {failures.length > 0 && (
        <Notice tone="warn" className="mb-8" title="Some evidence is missing" action={<Button size="sm" to={`${base}/progress`}>View log</Button>}>
          These plugins failed, so dependent rules were not evaluated: <span className="font-mono text-[13px]">{failures.join(", ")}</span>.
        </Notice>
      )}

      <div className="grid gap-6 lg:grid-cols-12">
        <div className="lg:col-span-5 xl:col-span-4">
          {job.overall_risk_band && (
            <RiskCard className="h-full" score={job.overall_risk_score ?? 0} band={job.overall_risk_band} findings={s.findings}
              footer={s.scoring_model?.disclaimer ?? "Analytical prioritisation score, not a malware verdict."} />
          )}
        </div>
        <div className="grid gap-5 sm:grid-cols-2 lg:col-span-7 xl:col-span-8 2xl:grid-cols-3">
          <MetricCard to={`${base}/processes`} label="Processes" value={s.total_processes ?? 0} icon={<Cpu />}
            hint={`${s.hidden_candidates ?? 0} hidden · ${s.terminated_processes ?? 0} exited`} />
          <MetricCard to={`${base}/processes`} label="Suspicious processes" value={s.suspicious_processes ?? 0} icon={<ShieldAlert />}
            tone={(s.suspicious_processes ?? 0) ? "danger" : undefined} hint="Risk score 30 or higher" />
          <MetricCard to={`${base}/memory`} label="Memory indicators" value={s.injected_memory_indicators ?? 0} icon={<MemoryStick />}
            tone={(s.injected_memory_indicators ?? 0) ? "warning" : undefined} hint="malfind executable private regions" />
          <MetricCard to={`${base}/network`} label="Network connections" value={s.network_connections ?? 0} icon={<Network />}
            hint={`${s.external_connections ?? 0} external · ${s.suspicious_connections ?? 0} flagged`} />
          <MetricCard to={`${base}/iocs`} label="IOCs" value={s.iocs ?? 0} icon={<Fingerprint />} tone="accent" hint="Indicators extracted" />
          <MetricCard to={`${base}/findings`} label="High-severity findings" value={s.high_severity_findings ?? 0} icon={<ShieldAlert />}
            tone={(s.high_severity_findings ?? 0) ? "danger" : undefined} hint={`${s.findings ?? 0} findings in total`} />
        </div>
      </div>

      <div className="mt-8 grid gap-6 lg:grid-cols-12">
        <Card className="lg:col-span-7 xl:col-span-8" icon={<Sparkles />} title="AI investigation summary" subtitle="Generated only from evidence stored for this analysis"
          actions={<>
            {summaryAi.data && <ValidationBadge v={summaryAi.data.validation as { status?: "grounded" | "uncertain" | "rejected" }} />}
            <Button size="sm" variant="subtle" to={`${base}/assistant`} icon={<Bot />}>Ask a question</Button>
          </>}>
          {summaryAi.loading && !summaryAi.data ? <SkeletonAI /> : summaryAi.error ? <ErrorState compact message={summaryAi.error} onRetry={summaryAi.reload} /> :
            summaryAi.data && (
              <>
                <div className="max-h-[440px] overflow-y-auto pr-2"><Markdown text={summaryAi.data.markdown} onCite={(id) => cite(id)} /></div>
                <p className="mt-4 border-t border-line pt-4 text-xs text-muted">Engine: {summaryAi.data.provider}. Click an evidence ID to open it.</p>
              </>
            )}
        </Card>
        <Card className="lg:col-span-5 xl:col-span-4" title="Memory image">
          <KeyValue rows={[
            ["File", <span key="f" className="break-all">{job.image.original_filename}</span>],
            ["SHA-256", <span key="h" className="flex items-start gap-1"><Mono>{job.image.sha256}</Mono><CopyButton text={job.image.sha256} compact /></span>],
            ["Size", fmtBytes(job.image.size_bytes)],
            ["Kernel", os.kernel_base ? <span key="k"><Mono>{os.kernel_base}</Mono> <span className="text-muted">NT {os.nt_version ?? "?"} · build {os.build ?? "?"}</span></span> : null],
            ["Symbols", os.suggested_symbols ? <Mono key="s">{os.suggested_symbols}</Mono> : null],
            ["System time", os.system_time ?? null],
            ["Identification", <span key="c" className="capitalize">{os.confidence ?? "low"} confidence{os.uncertain?.length ? <span className="mt-1 block text-xs normal-case text-sev-medium-text">Uncertain: {os.uncertain.join(", ")}</span> : null}</span>],
            ["Engine", job.volatility_version ?? null],
          ]} />
        </Card>
      </div>

      <div className="mt-8 grid gap-6 lg:grid-cols-12">
        <Card className="lg:col-span-7" title="Highest-risk processes" subtitle="Click a bar to open the process. Dashed lines mark the 30 / 60 / 80 band thresholds.">
          {procs.data ? <TopRiskChart processes={procs.data} onSelect={goProc} /> : <SkeletonChart />}
        </Card>
        <Card className="lg:col-span-5" title="Severity distribution" subtitle="Findings produced by the rule engine">
          <SeverityChart counts={s.severity_counts ?? {}} height={280} />
        </Card>
      </div>

      <div className="mt-8 grid gap-6 lg:grid-cols-12">
        <Card className="lg:col-span-7" title="Suspicious process timeline" subtitle="Creation time (UTC) against risk score">
          {procs.data ? <ProcessTimelineChart processes={procs.data} onSelect={goProc} /> : <SkeletonChart />}
        </Card>
        <Card className="lg:col-span-5" title="Findings by category">
          <CategoryChart counts={s.category_counts ?? {}} />
        </Card>
      </div>

      <Card className="mt-8" title="Network activity by process" subtitle="Endpoints recovered by netscan, split into internal and external">
        {net.data ? <NetworkChart connections={net.data} /> : <SkeletonChart />}
      </Card>
    </>
  );
}
