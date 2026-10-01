import { Download, FileJson, FileSpreadsheet, FileText, Globe } from "lucide-react";
import { useState } from "react";
import { useAnalysis } from "../components/layout/AppLayout";
import { Button, Card, CopyButton, EmptyState, ErrorState, Loading, Mono, Notice, PageHeader } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api, download } from "../services/api";
import { fmtBytes, fmtTime } from "../services/format";

const FORMATS = [
  { key: "pdf", label: "PDF report", icon: <FileText className="h-5 w-5" />, desc: "Printable forensic report with charts, custody appendix and plugin hashes." },
  { key: "html", label: "HTML report", icon: <Globe className="h-5 w-5" />, desc: "Self-contained HTML report with inline SVG charts." },
  { key: "json", label: "JSON export", icon: <FileJson className="h-5 w-5" />, desc: "Complete structured data for tooling and reproducibility." },
  { key: "csv", label: "CSV bundle (ZIP)", icon: <FileSpreadsheet className="h-5 w-5" />, desc: "Findings, processes, network, IOCs, timeline and custody as CSV." },
];

const SECTIONS = ["Executive Summary", "Case Information", "Memory Image Information", "SHA-256 Hash", "Environment", "Analysis Methodology",
  "Process Analysis", "Suspicious Processes", "Memory Injection Findings", "Network Analysis", "IOC Findings", "YARA Findings",
  "Risk Scoring", "AI Analysis", "Timeline", "Limitations", "Recommended Next Steps", "Appendix (chain of custody, plugin hashes)"];

export default function ReportsPage() {
  const { job, jobId } = useAnalysis();
  const reports = useApi(() => api.reports(jobId), [jobId]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const generate = async (fmt: string) => {
    setBusy(fmt);
    setError(null);
    try {
      const r = await api.generateReport(jobId, fmt);
      reports.reload();
      await download(`/api/reports/${r.id}/download`, undefined, `report.${fmt}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <PageHeader title="Reports" subtitle="Each generated report is hashed (SHA-256) and the hash is recorded in the chain of custody." />
      {job.image.is_demo && <div className="mb-4"><Notice tone="danger">Reports for this analysis are watermarked <b>DEMO DATA - NOT REAL FORENSIC EVIDENCE</b>.</Notice></div>}
      {error && <div className="mb-4"><ErrorState message={error} /></div>}
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {FORMATS.map((f) => (
          <div key={f.key} className="flex flex-col rounded-xl border border-line bg-surface p-4">
            <div className="flex items-center gap-2 font-medium text-ink"><span className="text-accent">{f.icon}</span>{f.label}</div>
            <p className="mt-1 flex-1 text-sm text-muted">{f.desc}</p>
            <Button variant="primary" className="mt-3 justify-center" onClick={() => generate(f.key)} disabled={busy !== null}>
              {busy === f.key ? "Generating..." : "Generate & download"}
            </Button>
          </div>
        ))}
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card title="Generated reports" className="xl:col-span-2">
          {reports.loading && !reports.data ? <Loading /> : !reports.data?.length ? <EmptyState title="No reports generated yet" /> : (
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase text-muted"><tr><th className="py-1 pr-3">Format</th><th className="pr-3">Generated</th><th className="pr-3">Size</th><th className="pr-3">SHA-256</th><th /></tr></thead>
              <tbody className="divide-y divide-line">{reports.data.map((r) => (
                <tr key={r.id}>
                  <td className="py-2 pr-3 font-medium uppercase text-ink">{r.report_format}</td>
                  <td className="pr-3 text-xs text-muted">{fmtTime(r.generated_at)}</td>
                  <td className="pr-3">{fmtBytes(r.size_bytes)}</td>
                  <td className="pr-3"><Mono>{r.sha256.slice(0, 24)}...</Mono> <CopyButton text={r.sha256} /></td>
                  <td><Button variant="ghost" onClick={() => download(`/api/reports/${r.id}/download`, undefined, `report.${r.report_format}`)}><Download className="h-4 w-4" /></Button></td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </Card>
        <Card title="Report contents">
          <ol className="list-decimal space-y-0.5 pl-5 text-sm text-ink-2">{SECTIONS.map((s) => <li key={s}>{s}</li>)}</ol>
        </Card>
      </div>
    </>
  );
}
