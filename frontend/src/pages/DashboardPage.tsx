import { FlaskConical, FolderPlus } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Page } from "../components/layout/AppLayout";
import { SeverityChart } from "../components/charts";
import { Button, Card, EmptyState, ErrorState, Loading, Notice, PageHeader, RiskBadge, StatCard, StatusPill } from "../components/ui";
import { useApi, usePolling } from "../hooks/useApi";
import { api } from "../services/api";
import { fmtTime } from "../services/format";

export default function DashboardPage() {
  const nav = useNavigate();
  const { data, error, loading, reload } = useApi(() => api.dashboard(), []);
  const status = useApi(() => api.systemStatus(), []);
  const [demoBusy, setDemoBusy] = useState(false);
  const [demoErr, setDemoErr] = useState<string | null>(null);
  usePolling(reload, 4000, (data?.running ?? 0) > 0);

  const loadDemo = async () => {
    setDemoBusy(true);
    setDemoErr(null);
    try {
      const job = await api.loadDemo();
      nav(`/analysis/${job.id}/progress`);
    } catch (e) {
      setDemoErr((e as Error).message);
      setDemoBusy(false);
    }
  };

  const t = data?.totals ?? {};
  return (
    <Page>
      <PageHeader title="Dashboard" subtitle="Overview across all investigations (latest completed analysis per memory image)."
        actions={<>
          <Button onClick={loadDemo} disabled={demoBusy}><FlaskConical className="h-4 w-4" />{demoBusy ? "Loading demo..." : "Load demo case"}</Button>
          <Link to="/investigations/new"><Button variant="primary"><FolderPlus className="h-4 w-4" />New investigation</Button></Link>
        </>} />
      {demoErr && <div className="mb-4"><ErrorState message={demoErr} /></div>}
      {status.data && !status.data.volatility.available && (
        <div className="mb-4"><Notice tone="warn">Volatility 3 was not found on the server: {status.data.volatility.message} Demo mode still works.</Notice></div>
      )}
      {loading && !data ? <Loading /> : error ? <ErrorState message={error} onRetry={reload} /> : data && (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
            <StatCard label="Cases" value={data.cases} hint={`${data.open_cases} open`} />
            <StatCard label="Processes" value={t.total_processes ?? 0} />
            <StatCard label="Suspicious processes" value={t.suspicious_processes ?? 0} tone={(t.suspicious_processes ?? 0) > 0 ? "danger" : undefined} />
            <StatCard label="Connections" value={t.network_connections ?? 0} />
            <StatCard label="Suspicious connections" value={t.suspicious_connections ?? 0} tone={(t.suspicious_connections ?? 0) > 0 ? "warn" : undefined} />
            <StatCard label="Injection indicators" value={t.injected_memory_indicators ?? 0} />
            <StatCard label="IOCs" value={t.iocs ?? 0} />
            <StatCard label="High-severity findings" value={t.high_severity_findings ?? 0} tone={(t.high_severity_findings ?? 0) > 0 ? "danger" : undefined} />
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-3">
            <Card title="Findings by severity" className="lg:col-span-1">
              <SeverityChart counts={data.severity_counts} />
            </Card>
            <Card title="Recent analyses" className="lg:col-span-2" pad={false}>
              {data.recent_analyses.length === 0 ? (
                <EmptyState title="No analyses yet">Create an investigation and upload a memory image, or load the demo case.</EmptyState>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="bg-surface-2 text-left text-xs uppercase text-muted">
                      <tr><th className="px-4 py-2">Analysis</th><th className="px-4 py-2">Case</th><th className="px-4 py-2">Image</th><th className="px-4 py-2">Status</th><th className="px-4 py-2">Risk</th><th className="px-4 py-2">Created</th></tr>
                    </thead>
                    <tbody className="divide-y divide-line">
                      {data.recent_analyses.map((a) => (
                        <tr key={a.id} className="cursor-pointer hover:bg-surface-2" onClick={() => nav(a.status.startsWith("completed") ? `/analysis/${a.id}` : `/analysis/${a.id}/progress`)}>
                          <td className="px-4 py-2 font-medium text-ink">#{a.id}</td>
                          <td className="px-4 py-2 text-ink-2">{a.case_number}</td>
                          <td className="max-w-[260px] truncate px-4 py-2 text-ink-2">{a.is_demo && <span className="mr-1 rounded bg-sev-critical/20 px-1 text-[10px] font-bold text-[#f08a8a]">DEMO</span>}{a.image}</td>
                          <td className="px-4 py-2"><StatusPill status={a.status} />{a.status === "running" && <span className="ml-2 text-xs text-muted tabular">{a.progress}%</span>}</td>
                          <td className="px-4 py-2"><RiskBadge score={a.risk_score} band={a.risk_band} /></td>
                          <td className="whitespace-nowrap px-4 py-2 text-xs text-muted">{fmtTime(a.created_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <Card title="Recent chain-of-custody events">
              {data.recent_custody.length === 0 ? <EmptyState title="No events yet" /> : (
                <ul className="space-y-2 text-sm">
                  {data.recent_custody.map((c, i) => (
                    <li key={i} className="flex gap-3">
                      <span className="w-40 shrink-0 text-xs text-muted">{fmtTime(c.timestamp)}</span>
                      <span className="min-w-0"><span className="font-medium text-ink">{c.action.replace(/_/g, " ")}</span> <span className="text-muted">by {c.actor}</span>
                        {c.details && <span className="block truncate text-xs text-muted">{c.details}</span>}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <Card title="Platform status">
              {status.data ? (
                <ul className="space-y-2 text-sm text-ink-2">
                  <li>Volatility 3: {status.data.volatility.available ? <span className="text-good">available {status.data.volatility.version ?? ""}</span> : <span className="text-sev-high">not installed</span>}</li>
                  <li>YARA (yara-python): {status.data.yara_python ? <span className="text-good">available</span> : <span className="text-muted">not installed - YARA scanning relies on Volatility's YARA backend</span>}</li>
                  <li>AI provider: <span className="font-medium text-ink">{status.data.ai.provider}</span>{status.data.ai.model && <span className="text-muted"> ({status.data.ai.model})</span>}</li>
                  <li>Accepted formats: {status.data.limits.allowed_extensions.join(", ")}</li>
                </ul>
              ) : <Loading />}
            </Card>
          </div>
        </>
      )}
    </Page>
  );
}
