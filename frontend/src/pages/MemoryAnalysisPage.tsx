import { useState } from "react";
import { Link } from "react-router-dom";
import { useAnalysis } from "../components/layout/AppLayout";
import { DataTable } from "../components/ui/DataTable";
import { Card, Drawer, ErrorState, Loading, Mono, Notice, PageHeader, SeverityBadge } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { confidenceLabel } from "../services/format";
import type { Finding, Region } from "../types";

export default function MemoryAnalysisPage() {
  const { jobId } = useAnalysis();
  const regions = useApi(() => api.regions(jobId), [jobId]);
  const findings = useApi(() => api.findings(jobId, { category: "memory" }), [jobId]);
  const yara = useApi(() => api.yaraMatches(jobId), [jobId]);
  const [open, setOpen] = useState<Region | null>(null);

  const reasonFor = (r: Region): Finding | undefined =>
    (findings.data ?? []).filter((f) => f.pid === r.pid && f.evidence.some((e) => e.ref === `MEM:${r.pid}:${r.start}`))
      .sort((a, b) => b.confidence - a.confidence)[0];

  return (
    <>
      <PageHeader title="Memory analysis" subtitle="malfind (private executable memory) and targeted vadinfo regions, with injection indicators and YARA matches." />
      <div className="mb-4"><Notice tone="warn">Injection findings are <b>indicators, not definitive proof of malware</b>. JIT compilers (.NET, browsers), security products and packers also create executable private memory.</Notice></div>

      <Card title="Injection indicators" className="mb-4">
        {findings.loading && !findings.data ? <Loading /> : findings.error ? <ErrorState message={findings.error} /> : (
          <DataTable<Finding>
            rows={findings.data ?? []} rowKey={(f) => f.id} initialSort={{ key: "confidence", dir: "desc" }} empty="No memory-injection indicators."
            columns={[
              { key: "process_name", header: "Process", render: (f) => <Link className="text-accent hover:underline" to={`/analysis/${jobId}/processes/${f.pid}`}>{f.process_name}</Link> },
              { key: "pid", header: "PID", className: "tabular" },
              { key: "title", header: "Finding", render: (f) => <div><div className="text-ink">{f.title}</div><div className="text-xs text-muted">{f.finding}</div></div> },
              { key: "region", header: "Memory region / protection", sortValue: (f) => f.evidence[0]?.value,
                render: (f) => <div className="space-y-0.5">{f.evidence.filter((e) => e.artifact === "memory_region").slice(0, 3).map((e, i) => <Mono key={i} className="block">{e.value}</Mono>)}</div> },
              { key: "severity", header: "Severity", render: (f) => <SeverityBadge severity={f.severity} /> },
              { key: "confidence", header: "Confidence", render: (f) => `${confidenceLabel(f.confidence)} (${f.confidence})` },
            ]}
          />
        )}
      </Card>

      <Card title="Memory regions" className="mb-4">
        {regions.loading && !regions.data ? <Loading /> : regions.error ? <ErrorState message={regions.error} /> : (
          <DataTable<Region>
            rows={regions.data ?? []} rowKey={(r) => r.id} onRowClick={setOpen} empty="No regions recorded."
            rowClassName={(r) => (r.has_pe_header ? "bg-sev-high/10" : undefined)}
            columns={[
              { key: "process_name", header: "Process", render: (r) => <span className="text-ink">{r.process_name} <span className="text-muted tabular">({r.pid})</span></span> },
              { key: "source", header: "Source" },
              { key: "start", header: "Region", render: (r) => <Mono>{r.start} - {r.end}</Mono> },
              { key: "protection", header: "Protection" },
              { key: "tag", header: "Tag" },
              { key: "private_memory", header: "Private", render: (r) => String(r.private_memory ?? "?") },
              { key: "has_pe_header", header: "PE header", sortValue: (r) => Number(r.has_pe_header), render: (r) => r.has_pe_header ? <span className="font-semibold text-sev-high">MZ</span> : "-" },
              { key: "reason", header: "Reason", sortValue: (r) => reasonFor(r)?.title, render: (r) => <span className="text-xs text-ink-2">{reasonFor(r)?.title ?? (r.mapped_file ? `mapped: ${r.mapped_file}` : "-")}</span> },
            ]}
          />
        )}
      </Card>

      <Card title="YARA matches">
        {yara.data && yara.data.length > 0 ? (
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-muted"><tr><th className="py-1 pr-3">Rule</th><th className="pr-3">Process</th><th className="pr-3">Offset</th><th className="pr-3">Evidence</th><th>Severity</th></tr></thead>
            <tbody className="divide-y divide-line">{yara.data.map((y) => (
              <tr key={y.id}><td className="py-1.5 pr-3 font-medium text-ink">{y.rule_name}</td><td className="pr-3">{y.process_name} ({y.pid})</td>
                <td className="pr-3"><Mono>{y.offset}</Mono></td><td className="pr-3"><Mono>{y.component} {y.matched_value}</Mono></td><td><SeverityBadge severity={y.severity} /></td></tr>
            ))}</tbody>
          </table>
        ) : <p className="text-sm text-muted">No YARA matches, or YARA scanning was not performed for this analysis.</p>}
        <p className="mt-2 text-xs text-muted">A YARA match alone does not prove malicious activity; it depends entirely on rule quality.</p>
      </Card>

      <Drawer open={!!open} onClose={() => setOpen(null)} title={open && <span>{open.process_name} ({open.pid}) - <Mono>{open.start}</Mono></span>}>
        {open && (
          <div className="space-y-3 text-sm">
            <div className="grid grid-cols-2 gap-2 text-ink-2">
              <div>Protection: <b className="text-ink">{open.protection}</b></div><div>Tag: {open.tag}</div>
              <div>Private: {String(open.private_memory)}</div><div>Commit charge: {open.commit_charge ?? "-"}</div>
              <div>Source: {open.source}</div><div>PE header: {open.has_pe_header ? "yes" : "no"}</div>
            </div>
            {reasonFor(open) && <div className="rounded-lg border border-line p-3"><SeverityBadge severity={reasonFor(open)!.severity} /> <span className="ml-1 text-ink">{reasonFor(open)!.finding}</span></div>}
            {open.hexdump && <><h4 className="text-xs uppercase text-muted">Hexdump</h4><pre className="overflow-x-auto rounded bg-page p-3 font-mono text-xs">{open.hexdump}</pre></>}
            {open.disasm && <><h4 className="text-xs uppercase text-muted">Disassembly</h4><pre className="overflow-x-auto rounded bg-page p-3 font-mono text-xs">{open.disasm}</pre></>}
          </div>
        )}
      </Drawer>
    </>
  );
}
