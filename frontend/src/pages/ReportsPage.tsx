import { Download, Eye, FileJson, FileSpreadsheet, FileText, Globe, Loader2, RefreshCw, ShieldCheck } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { useAnalysis, useAnalysisCrumbs } from "../components/layout/AppLayout";
import { Badge, Button, Card, CopyButton, DataTable, EmptyState, ErrorState, Notice, PageHeader, Skeleton, SkeletonText } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useNow } from "../hooks/useShell";
import { useToast } from "../hooks/useToast";
import { api, download, fetchText } from "../services/api";
import { fmtBytes, fmtRelative, fmtTime } from "../services/format";
import type { Report } from "../types";

type Fmt = Report["report_format"];
const FORMATS: { key: Fmt; label: string; icon: ReactNode; desc: string }[] = [
  { key: "pdf", label: "PDF report", icon: <FileText />, desc: "Printable forensic report with charts, custody appendix and plugin hashes." },
  { key: "html", label: "HTML report", icon: <Globe />, desc: "Self-contained HTML report with inline SVG charts. Previewable here." },
  { key: "json", label: "JSON export", icon: <FileJson />, desc: "Complete structured data for tooling and reproducibility." },
  { key: "csv", label: "CSV bundle", icon: <FileSpreadsheet />, desc: "Findings, processes, network, IOCs, timeline and custody as CSV (ZIP)." },
];
const ICON: Record<Fmt, ReactNode> = { pdf: <FileText />, html: <Globe />, json: <FileJson />, csv: <FileSpreadsheet /> };
const SECTIONS = ["Executive summary", "Case information", "Memory image information", "SHA-256 hash", "Environment", "Analysis methodology",
  "Process analysis", "Suspicious processes", "Memory injection findings", "Network analysis", "IOC findings", "YARA findings",
  "Risk scoring", "AI analysis", "Timeline", "Limitations", "Recommended next steps", "Appendix: custody & plugin hashes"];

export default function ReportsPage() {
  const { job, jobId } = useAnalysis();
  useAnalysisCrumbs({ label: "Reports" });
  const toast = useToast();
  const now = useNow();
  const reports = useApi(() => api.reports(jobId), [jobId]);
  const [busy, setBusy] = useState<Fmt | null>(null);
  const [selected, setSelected] = useState<Report | null>(null);
  const [preview, setPreview] = useState<{ id: number; text: string } | null>(null);
  const [previewErr, setPreviewErr] = useState<string | null>(null);
  const [previewBusy, setPreviewBusy] = useState(false);

  const name = (r: Report) => `${job.case_number}-analysis-${jobId}-report-${r.id}.${r.report_format === "csv" ? "zip" : r.report_format}`;

  useEffect(() => {
    if (!selected && reports.data?.length) setSelected([...reports.data].sort((a, b) => b.id - a.id).find((r) => r.report_format === "html") ?? reports.data[0]);
  }, [reports.data, selected]);

  useEffect(() => {
    if (!selected || (selected.report_format !== "html" && selected.report_format !== "json") || preview?.id === selected.id) return;
    setPreviewBusy(true);
    setPreviewErr(null);
    fetchText(`/api/reports/${selected.id}/download`)
      .then((text) => setPreview({ id: selected.id, text: selected.report_format === "json" ? pretty(text) : text }))
      .catch((e: Error) => setPreviewErr(e.message))
      .finally(() => setPreviewBusy(false));
  }, [selected, preview?.id]);

  const generate = async (fmt: Fmt) => {
    setBusy(fmt);
    try {
      const r = await api.generateReport(jobId, fmt);
      reports.reload();
      setSelected(r);
      toast({ tone: "success", title: `${fmt.toUpperCase()} report generated`, description: `SHA-256 ${r.sha256.slice(0, 16)}... recorded in the chain of custody.` });
    } catch (e) {
      toast({ tone: "error", title: "Report generation failed", description: (e as Error).message });
    } finally {
      setBusy(null);
    }
  };
  const dl = (r: Report) => download(`/api/reports/${r.id}/download`, undefined, name(r))
    .catch((e: Error) => toast({ tone: "error", title: "Download failed", description: e.message }));

  const rows = [...(reports.data ?? [])].sort((a, b) => b.id - a.id);

  return (
    <>
      <PageHeader title="Reports" subtitle="Every generated report is hashed (SHA-256) and the hash is recorded in the chain of custody." />
      {job.image.is_demo && <Notice tone="danger" className="mb-8">Reports for this analysis are watermarked <b>DEMO DATA - NOT REAL FORENSIC EVIDENCE</b>.</Notice>}

      <section aria-label="Generate a report" className="mb-10 grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
        {FORMATS.map((f) => (
          <div key={f.key} className="flex flex-col rounded-2xl border border-line bg-surface p-6 shadow-card transition-[border-color,box-shadow] hover:border-line-strong hover:shadow-raised">
            <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-accent-soft text-accent-text [&_svg]:h-5 [&_svg]:w-5">{f.icon}</span>
            <div className="mt-5 text-[15px] font-semibold text-ink">{f.label}</div>
            <p className="mt-1.5 flex-1 text-[13px] leading-relaxed text-muted">{f.desc}</p>
            <Button variant="secondary" className="mt-6 w-full" onClick={() => generate(f.key)} disabled={busy !== null}
              icon={busy === f.key ? <Loader2 className="animate-spin" /> : undefined}>{busy === f.key ? "Generating..." : "Generate"}</Button>
          </div>
        ))}
      </section>

      <div className="grid gap-6 xl:grid-cols-12">
        <div className="space-y-6 xl:col-span-8">
          <Card title="Generated reports" pad={false}>
            {reports.error ? <div className="p-6"><ErrorState compact message={reports.error} onRetry={reports.reload} /></div> : !reports.loading && rows.length === 0 ? (
              <EmptyState title="No reports generated yet" icon={<FileText />}>Choose a format above to generate the first report for this analysis.</EmptyState>
            ) : (
              <DataTable<Report> rows={rows} loading={reports.loading && !reports.data} rowKey={(r) => r.id} search={false} pageSize={8}
                onRowClick={setSelected} rowClassName={(r) => (selected?.id === r.id ? "bg-accent-soft/60" : undefined)}
                columns={[
                  { key: "id", header: "Report", render: (r) => (
                    <div className="flex min-w-0 items-center gap-3">
                      <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-muted [&_svg]:h-4 [&_svg]:w-4">{ICON[r.report_format]}</span>
                      <div className="min-w-0">
                        <div className="max-w-[300px] truncate font-medium text-ink">{name(r)}</div>
                        <div className="mt-0.5 flex items-center gap-1 font-mono text-xs text-muted" title={r.sha256}>{r.sha256.slice(0, 16)}…<CopyButton text={r.sha256} compact /></div>
                      </div>
                    </div>) },
                  { key: "report_format", header: "Format", render: (r) => <Badge className="uppercase">{r.report_format}</Badge> },
                  { key: "generated_at", header: "Generated", render: (r) => <span className="whitespace-nowrap text-[13px] text-muted" title={fmtTime(r.generated_at)}>{fmtRelative(r.generated_at, now)}</span> },
                  { key: "status", header: "Status", sortable: false, render: () => <Badge tone="success" icon={<ShieldCheck />}>Ready · hashed</Badge> },
                  { key: "size_bytes", header: "Size", align: "right", render: (r) => <span className="tabular text-[13px]">{fmtBytes(r.size_bytes)}</span> },
                  { key: "actions", header: "", sortable: false, align: "right", render: (r) => (
                    <span className="inline-flex gap-1" onClick={(e) => e.stopPropagation()}>
                      <Button size="sm" variant="ghost" aria-label="Preview" title="Preview" onClick={() => setSelected(r)}><Eye /></Button>
                      <Button size="sm" variant="ghost" aria-label="Download" title="Download" onClick={() => dl(r)}><Download /></Button>
                      <Button size="sm" variant="ghost" aria-label="Regenerate" title="Regenerate" disabled={busy !== null} onClick={() => generate(r.report_format)}><RefreshCw /></Button>
                    </span>) },
                ]} />
            )}
          </Card>

          <Card title="Preview" subtitle={selected ? name(selected) : "Select a report"}
            actions={selected && <Button size="sm" icon={<Download />} onClick={() => dl(selected)}>Download</Button>}>
            {!selected ? <EmptyState compact title="Nothing to preview" icon={<Eye />}>Generate an HTML or JSON report to preview it here.</EmptyState>
              : selected.report_format === "pdf" || selected.report_format === "csv" ? (
                <EmptyState compact title={`${selected.report_format.toUpperCase()} preview not available in the browser`} icon={ICON[selected.report_format]}
                  action={<Button variant="primary" icon={<Download />} onClick={() => dl(selected)}>Download {selected.report_format.toUpperCase()}</Button>}>
                  Download the file to open it. HTML and JSON reports can be previewed here.
                </EmptyState>
              ) : previewBusy || preview?.id !== selected.id ? (
                previewErr ? <ErrorState compact message={previewErr} /> : <div className="space-y-4"><Skeleton className="h-6 w-1/3" /><SkeletonText lines={8} /></div>
              ) : selected.report_format === "html" ? (
                <iframe title="HTML report preview" sandbox="" srcDoc={preview.text}
                  className="h-[760px] w-full rounded-xl border border-line bg-white" />
              ) : (
                <pre className="max-h-[760px] overflow-auto rounded-xl border border-line bg-page/60 p-5 font-mono text-xs leading-relaxed text-ink-2">{preview.text}</pre>
              )}
          </Card>
        </div>

        <Card className="xl:col-span-4 xl:self-start" title="Report contents" subtitle="18 sections in PDF and HTML reports">
          <ol className="space-y-2.5">
            {SECTIONS.map((s, i) => (
              <li key={s} className="flex gap-3 text-sm text-ink-2">
                <span className="w-6 shrink-0 text-right font-mono text-xs leading-5 text-faint">{String(i + 1).padStart(2, "0")}</span>{s}
              </li>
            ))}
          </ol>
        </Card>
      </div>
    </>
  );
}

function pretty(text: string): string {
  try {
    const out = JSON.stringify(JSON.parse(text), null, 2);
    return out.length > 250_000 ? `${out.slice(0, 250_000)}\n\n... truncated in preview - download for the full export` : out;
  } catch {
    return text;
  }
}
