import { Eye, MemoryStick, ScanLine, Sparkles } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { EvidencePanel, FindingCard } from "../components/forensic/cards";
import { useAnalysis, useAnalysisCrumbs } from "../components/layout/AppLayout";
import { ExplanationPanel } from "../components/process/ExplanationPanel";
import {
  Badge, Button, Card, cx, DataTable, Drawer, EmptyState, ErrorState, KeyValue, Mono, Notice, PageHeader, SectionHeader, SegmentedControl,
  SeverityBadge, sevRank, Skeleton, SkeletonTable,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { Finding, Region, YaraMatch } from "../types";

type RegionFilter = "all" | "exec" | "rwx" | "pe" | "malfind" | "vadinfo";
const isExec = (r: Region) => (r.protection ?? "").includes("EXECUTE");
const isRwx = (r: Region) => (r.protection ?? "").includes("EXECUTE_READWRITE") || (r.protection ?? "").includes("EXECUTE_WRITECOPY");

export default function MemoryAnalysisPage() {
  const { jobId } = useAnalysis();
  useAnalysisCrumbs({ label: "Memory Analysis" });
  const regions = useApi(() => api.regions(jobId), [jobId]);
  const findings = useApi(() => api.findings(jobId, { category: "memory" }), [jobId]);
  const yara = useApi(() => api.yaraMatches(jobId), [jobId]);
  const [filter, setFilter] = useState<RegionFilter>("all");
  const [region, setRegion] = useState<Region | null>(null);
  const [explain, setExplain] = useState<Finding | null>(null);

  const all = regions.data ?? [];
  const mem = useMemo(() => [...(findings.data ?? [])].sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || b.confidence - a.confidence), [findings.data]);
  const reasonFor = (r: Region): Finding | undefined =>
    mem.filter((f) => f.pid === r.pid && f.evidence.some((e) => e.ref === `MEM:${r.pid}:${r.start}`)).sort((a, b) => b.confidence - a.confidence)[0];
  const suspicious = all.filter((r) => reasonFor(r) || r.has_pe_header)
    .sort((a, b) => sevRank(reasonFor(a)?.severity ?? "info") - sevRank(reasonFor(b)?.severity ?? "info") || Number(b.has_pe_header) - Number(a.has_pe_header)).slice(0, 6);
  const rows = all.filter((r) => filter === "all" || (filter === "exec" ? isExec(r) : filter === "rwx" ? isRwx(r) : filter === "pe" ? r.has_pe_header : r.source.endsWith(filter)));

  const stats = [
    { label: "Regions recorded", value: all.length },
    { label: "Executable", value: all.filter(isExec).length },
    { label: "RWX permissions", value: all.filter(isRwx).length, warn: true },
    { label: "PE headers (MZ)", value: all.filter((r) => r.has_pe_header).length, warn: true },
    { label: "Injection indicators", value: mem.length, warn: true },
    { label: "YARA matches", value: yara.data?.length ?? 0, warn: true },
  ];

  return (
    <>
      <PageHeader title="Memory Analysis" subtitle="malfind (private executable memory) and targeted vadinfo regions, with injection indicators, VAD analysis and YARA matches." />
      <Notice tone="warn" className="mb-8">Injection findings are <b>indicators, not definitive proof of malware</b>. JIT compilers (.NET, browsers), security products and packers also create executable private memory.</Notice>

      <Card className="mb-10">
        {regions.loading && !regions.data ? <Skeleton className="h-14" /> : (
          <div className="grid grid-cols-2 gap-x-8 gap-y-6 sm:grid-cols-3 xl:grid-cols-6">
            {stats.map((s) => (
              <div key={s.label}>
                <div className="text-[13px] text-muted">{s.label}</div>
                <div className={cx("mt-1 text-2xl font-semibold tracking-[-0.02em] tabular", s.warn && s.value ? "text-sev-high-text" : "text-ink")}>{s.value}</div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <section className="mb-12">
        <SectionHeader title="Injection indicators" subtitle="Memory-category findings from the rule engine, highest severity first" />
        {findings.loading && !findings.data ? <div className="grid gap-4 xl:grid-cols-2">{[0, 1].map((i) => <Skeleton key={i} className="h-48 rounded-xl" />)}</div>
          : findings.error ? <ErrorState compact message={findings.error} onRetry={findings.reload} />
            : mem.length === 0 ? <Card><EmptyState compact title="No memory-injection indicators" icon={<MemoryStick />} /></Card>
              : <div className="grid gap-4 xl:grid-cols-2">{mem.map((f) => <FindingCard key={f.id} finding={f} jobId={jobId} onOpen={setExplain} />)}</div>}
      </section>

      {suspicious.length > 0 && (
        <section className="mb-12">
          <SectionHeader title="Suspicious memory regions" subtitle="Regions attributed to a finding or carrying a PE header" />
          <div className="grid gap-5 xl:grid-cols-2">
            {suspicious.map((r) => {
              const f = reasonFor(r);
              return (
                <EvidencePanel key={r.id} title={r.start} severity={f?.severity ?? "high"}
                  eyebrow={<><Badge tone="accent">{r.source.replace("windows.", "")}</Badge><span>Memory region</span></>}
                  actions={<>
                    <Button size="sm" icon={<Eye />} onClick={() => setRegion(r)}>View evidence</Button>
                    {f && <Button size="sm" variant="subtle" icon={<Sparkles />} onClick={() => setExplain(f)}>Explain with AI</Button>}
                  </>}>
                  <KeyValue cols={2} rows={[
                    ["Protection", <span key="p" className={cx("font-mono text-[13px]", isRwx(r) && "font-semibold text-sev-high-text")}>{r.protection ?? "?"}</span>],
                    ["Status", <Badge key="s" tone="danger">Suspicious</Badge>],
                    ["Process", <Link key="pr" to={`/analysis/${jobId}/processes/${r.pid}`} className="font-medium text-ink hover:text-accent-text hover:underline">{r.process_name} ({r.pid})</Link>],
                    ["Range", <Mono key="r" nowrap>{r.start} – {r.end}</Mono>],
                  ]} />
                  <p className="mt-5 text-sm leading-relaxed text-ink-2">
                    <span className="font-medium text-ink">Reason: </span>
                    {f ? f.title : "PE header in a memory region"}{r.has_pe_header && f && " - region begins with an MZ header"}; associated with PID {r.pid}.
                  </p>
                </EvidencePanel>
              );
            })}
          </div>
        </section>
      )}

      <section className="mb-12">
        <SectionHeader title="VAD analysis" subtitle="Every recorded region. Select a row for bytes and disassembly." />
        <Card pad={false}>
          {regions.loading && !regions.data ? <SkeletonTable /> : regions.error ? <div className="p-6"><ErrorState compact message={regions.error} onRetry={regions.reload} /></div> : (
            <DataTable<Region>
              rows={rows} rowKey={(r) => r.id} onRowClick={setRegion} empty="No regions match this filter." searchPlaceholder="Search process, address, tag..."
              rowAccent={(r) => (reasonFor(r) ? "var(--color-sev-high)" : r.has_pe_header ? "var(--color-sev-medium)" : undefined)}
              toolbar={<SegmentedControl label="Region filter" value={filter} onChange={setFilter} options={[
                { key: "all", label: "All" }, { key: "exec", label: "Executable" }, { key: "rwx", label: "RWX" }, { key: "pe", label: "PE header" },
                { key: "malfind", label: "malfind" }, { key: "vadinfo", label: "vadinfo" },
              ]} />}
              columns={[
                { key: "process_name", header: "Process", render: (r) => <span className="font-medium text-ink">{r.process_name} <span className="font-mono text-[13px] font-normal text-muted">{r.pid}</span></span> },
                { key: "start", header: "Region", render: (r) => <Mono nowrap>{r.start} – {r.end}</Mono> },
                { key: "protection", header: "Protection", render: (r) => <span className={cx("font-mono text-xs", isRwx(r) ? "font-semibold text-sev-high-text" : "text-ink-2")}>{r.protection ?? "?"}</span> },
                { key: "source", header: "Source", render: (r) => <Badge>{r.source.replace("windows.", "")}</Badge> },
                { key: "tag", header: "Tag", render: (r) => <span className="font-mono text-xs">{r.tag ?? "-"}</span> },
                { key: "has_pe_header", header: "PE", sortValue: (r) => Number(r.has_pe_header), render: (r) => r.has_pe_header ? <Badge tone="warning">MZ</Badge> : <span className="text-faint">-</span> },
                { key: "reason", header: "Reason", sortValue: (r) => reasonFor(r)?.title, render: (r) => <span className="text-[13px] text-ink-2">{reasonFor(r)?.title ?? (r.mapped_file ? `mapped: ${r.mapped_file}` : "-")}</span> },
              ]} />
          )}
        </Card>
      </section>

      <section id="yara" className="scroll-mt-40">
        <SectionHeader title="YARA matches" subtitle="A match depends entirely on rule quality - it is an indicator, not proof." />
        <Card pad={false}>
          <DataTable<YaraMatch> rows={yara.data ?? []} loading={yara.loading && !yara.data} rowKey={(y) => y.id} search={false}
            empty={<EmptyState compact title="No YARA matches" icon={<ScanLine />}>No rule matched, or YARA scanning was not performed for this analysis.</EmptyState>}
            columns={[
              { key: "rule_name", header: "Rule", render: (y) => <span className="font-medium text-ink">{y.rule_name}</span> },
              { key: "process_name", header: "Process", render: (y) => y.pid != null ? <Link to={`/analysis/${jobId}/processes/${y.pid}`} className="text-ink-2 hover:text-accent-text hover:underline">{y.process_name} ({y.pid})</Link> : "-" },
              { key: "offset", header: "Offset", render: (y) => <Mono>{y.offset}</Mono> },
              { key: "matched_value", header: "Matched", render: (y) => <Mono>{y.component} {y.matched_value}</Mono> },
              { key: "severity", header: "Severity", sortValue: (y) => sevRank(y.severity), render: (y) => <SeverityBadge severity={y.severity} /> },
            ]} />
        </Card>
      </section>

      <Drawer open={!!region} onClose={() => setRegion(null)} width="xl"
        title={region && <span className="font-mono">{region.start} – {region.end}</span>} subtitle={region && `${region.process_name} (PID ${region.pid}) · ${region.source}`}
        footer={region && <>
          {reasonFor(region) && <Button variant="subtle" icon={<Sparkles />} onClick={() => { const f = reasonFor(region)!; setRegion(null); setExplain(f); }}>Explain with AI</Button>}
          <Button to={`/analysis/${jobId}/processes/${region.pid}?tab=memory`}>Open process</Button>
        </>}>
        {region && (
          <div className="space-y-7">
            <KeyValue cols={2} rows={[
              ["Protection", <span key="p" className="font-mono text-[13px] font-semibold">{region.protection}</span>], ["VAD tag", region.tag],
              ["Private memory", String(region.private_memory)], ["Commit charge", region.commit_charge ?? "-"],
              ["PE header", region.has_pe_header ? "Yes (MZ)" : "No"], ["Mapped file", region.mapped_file ? <Mono key="m">{region.mapped_file}</Mono> : "None"],
            ]} />
            {reasonFor(region) && <div className="flex items-start gap-3 rounded-xl border border-line bg-surface-2/60 p-4"><SeverityBadge severity={reasonFor(region)!.severity} /><span className="text-sm text-ink">{reasonFor(region)!.finding}</span></div>}
            {region.hexdump && <div><h4 className="mb-2 text-xs font-semibold uppercase tracking-[0.06em] text-muted">Hexdump</h4><pre className="overflow-x-auto rounded-xl border border-line bg-page/60 p-4 font-mono text-xs leading-relaxed text-ink-2">{region.hexdump}</pre></div>}
            {region.disasm && <div><h4 className="mb-2 text-xs font-semibold uppercase tracking-[0.06em] text-muted">Disassembly</h4><pre className="overflow-x-auto rounded-xl border border-line bg-page/60 p-4 font-mono text-xs leading-relaxed text-muted">{region.disasm}</pre></div>}
            {!region.hexdump && !region.disasm && <p className="text-sm text-muted">No bytes were captured for this region (vadinfo records metadata only).</p>}
          </div>
        )}
      </Drawer>
      <Drawer open={!!explain} onClose={() => setExplain(null)} title={explain?.title} subtitle={explain && `F-${explain.id} · ${explain.rule_id}`}>
        {explain && <ExplanationPanel finding={explain} />}
      </Drawer>
    </>
  );
}
