import { useNavigate } from "react-router-dom";
import { useAnalysis } from "../components/layout/AppLayout";
import { CategoryChart, NetworkChart, ProcessTimelineChart, SeverityChart, TopRiskChart } from "../components/charts";
import { Card, CopyButton, ErrorState, KeyValue, Loading, Markdown, Mono, Notice, RiskMeter, StatCard } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { fmtBytes, fmtTime } from "../services/format";

export default function OverviewPage() {
  const { job, jobId } = useAnalysis();
  const nav = useNavigate();
  const procs = useApi(() => api.processes(jobId), [jobId]);
  const net = useApi(() => api.network(jobId), [jobId]);
  const summaryAi = useApi(() => api.aiSummary(jobId), [jobId]);
  const s = job.summary;
  const os = job.image.os_info ?? {};
  const goProc = (pid: number) => nav(`/analysis/${jobId}/processes/${pid}`);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
        <StatCard label="Total processes" value={s.total_processes ?? 0} hint={`${s.hidden_candidates ?? 0} hidden, ${s.terminated_processes ?? 0} exited`} />
        <StatCard label="Suspicious processes" value={s.suspicious_processes ?? 0} hint="risk >= 30" tone={(s.suspicious_processes ?? 0) ? "danger" : undefined} />
        <StatCard label="Network connections" value={s.network_connections ?? 0} hint={`${s.external_connections ?? 0} external`} />
        <StatCard label="Suspicious connections" value={s.suspicious_connections ?? 0} tone={(s.suspicious_connections ?? 0) ? "warn" : undefined} />
        <StatCard label="Injected memory indicators" value={s.injected_memory_indicators ?? 0} hint="malfind regions" />
        <StatCard label="IOCs" value={s.iocs ?? 0} />
        <StatCard label="High-severity findings" value={s.high_severity_findings ?? 0} tone={(s.high_severity_findings ?? 0) ? "danger" : undefined} />
        <div className="rounded-xl border border-line bg-surface px-4 py-3">
          <div className="text-xs font-medium uppercase tracking-wide text-muted">Overall risk</div>
          <div className="mt-1">{job.overall_risk_band && <RiskMeter score={job.overall_risk_score ?? 0} band={job.overall_risk_band} />}</div>
        </div>
      </div>

      {Object.keys(s.plugin_failures ?? {}).length > 0 && (
        <Notice tone="warn">Some evidence is missing because these plugins failed: {Object.keys(s.plugin_failures!).join(", ")}. See the analysis log.</Notice>
      )}

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Memory image" className="xl:col-span-1">
          <KeyValue rows={[
            ["Memory image", job.image.original_filename],
            ["OS", os.os_name ?? <span className="text-sev-medium">Unknown - could not be identified</span>],
            ["Architecture", os.architecture ?? "unknown"],
            ["Kernel", os.kernel_base ? <span key="k"><Mono>{os.kernel_base}</Mono> (NT {os.nt_version ?? "?"}, build {os.build ?? "?"})</span> : "unknown"],
            ["Symbols", <Mono key="s">{os.suggested_symbols ?? "unknown"}</Mono>],
            ["Hash (SHA-256)", <span key="h"><Mono>{job.image.sha256}</Mono> <CopyButton text={job.image.sha256} /></span>],
            ["Size", fmtBytes(job.image.size_bytes)],
            ["System time", os.system_time ?? "unknown"],
            ["Identification", <span key="c">{os.confidence ?? "low"} confidence{os.uncertain?.length ? <span className="block text-xs text-sev-medium">Uncertain: {os.uncertain.join(", ")}</span> : null}</span>],
            ["Analysis status", `${job.status.replace(/_/g, " ")} (${fmtTime(job.completed_at)})`],
          ]} />
        </Card>
        <Card title="AI investigation summary" className="xl:col-span-2"
          actions={summaryAi.data && <span className="text-xs text-muted">by {summaryAi.data.provider} - grounded in stored evidence</span>}>
          {summaryAi.loading && !summaryAi.data ? <Loading /> : summaryAi.error ? <ErrorState message={summaryAi.error} /> :
            summaryAi.data && <div className="max-h-[420px] overflow-y-auto pr-2"><Markdown text={summaryAi.data.markdown} /></div>}
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Severity distribution"><SeverityChart counts={s.severity_counts ?? {}} /></Card>
        <Card title="Process risk scores (top 10)" className="xl:col-span-2"
          actions={<span className="text-xs text-muted">dashed lines: 30 moderate, 60 high, 80 critical</span>}>
          {procs.data ? <TopRiskChart processes={procs.data} onSelect={goProc} /> : <Loading />}
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Suspicious process timeline (creation time vs risk)" className="xl:col-span-2">
          {procs.data ? <ProcessTimelineChart processes={procs.data} onSelect={goProc} /> : <Loading />}
        </Card>
        <Card title="Finding categories"><CategoryChart counts={s.category_counts ?? {}} /></Card>
      </div>

      <Card title="Network activity by process">{net.data ? <NetworkChart connections={net.data} /> : <Loading />}</Card>
      <p className="text-xs text-muted">{s.scoring_model?.disclaimer}</p>
    </div>
  );
}
