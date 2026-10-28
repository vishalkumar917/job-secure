import { FilterX, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useAnalysis, useAnalysisCrumbs } from "../components/layout/AppLayout";
import { ExplanationPanel } from "../components/process/ExplanationPanel";
import {
  Button, Card, ConfidenceMeter, cx, DataTable, Drawer, EmptyState, ErrorState, PageHeader, SegmentedControl, Select, SEV_VAR, SeverityBadge, sevRank,
  Skeleton, SourceTag,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useToast } from "../hooks/useToast";
import { api } from "../services/api";
import { CATEGORY_LABEL, FINDING_STATUS, findingStatusLabel } from "../services/format";
import type { Finding, Severity } from "../types";

const TILES: Severity[] = ["critical", "high", "medium", "low"];
const TILE_HINT: Record<string, string> = {
  critical: "Strong, corroborated indicators", high: "Likely malicious behaviour", medium: "Suspicious - needs context", low: "Weak or common signals",
};

export default function FindingsPage() {
  const { jobId } = useAnalysis();
  useAnalysisCrumbs({ label: "Findings" });
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const { data, error, loading, setData, reload } = useApi(() => api.findings(jobId), [jobId]);
  const [sev, setSev] = useState<Severity | "">("");
  const [status, setStatus] = useState("");
  const [cat, setCat] = useState("");
  const [proc, setProc] = useState("");
  const [minConf, setMinConf] = useState("0");
  const [open, setOpen] = useState<Finding | null>(null);

  const all = data ?? [];
  useEffect(() => {
    const id = Number(params.get("f"));
    if (id && data) setOpen(data.find((f) => f.id === id) ?? null);
  }, [params, data]);
  const closeDrawer = () => {
    setOpen(null);
    if (params.get("f")) setParams({}, { replace: true });
  };

  const opts = useMemo(() => ({
    cats: [...new Set(all.map((f) => f.category))].sort(),
    procs: [...new Set(all.map((f) => f.process_name).filter(Boolean) as string[])].sort(),
  }), [all]);
  const sevCount = (s: Severity) => all.filter((f) => f.severity === s).length;
  const statusCount = (s: string) => (s ? all.filter((f) => f.status === s).length : all.length);
  const rows = all.filter((f) => (!sev || f.severity === sev) && (!status || f.status === status)
    && (!cat || f.category === cat) && (!proc || f.process_name === proc) && f.confidence >= Number(minConf));
  const filtered = sev || status || cat || proc || minConf !== "0";
  const reset = () => { setSev(""); setStatus(""); setCat("");  setProc(""); setMinConf("0"); };

  const updateStatus = async (f: Finding, s: string) => {
    try {
      const updated = await api.updateFinding(f.id, s);
      setData(all.map((x) => (x.id === f.id ? updated : x)));
      if (open?.id === f.id) setOpen(updated);
      toast({ tone: "success", title: `Marked as ${findingStatusLabel(s).toLowerCase()}`, description: f.title });
    } catch (e) {
      toast({ tone: "error", title: "Status not updated", description: (e as Error).message });
    }
  };

  if (error) return <ErrorState title="Findings unavailable" message={error} onRetry={reload} />;

  return (
    <>
      <PageHeader title="Findings" subtitle="Output of the modular rule engine. Select a finding for its explainable-AI breakdown; set a status to track triage." />

      <section aria-label="Severity summary" className="mb-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {TILES.map((s) => {
          const n = sevCount(s);
          const on = sev === s;
          return (
            <button key={s} type="button" onClick={() => setSev(on ? "" : s)} aria-pressed={on}
              className={cx("group relative overflow-hidden rounded-2xl border bg-surface p-6 text-left shadow-card transition-[border-color,box-shadow,transform] duration-200 hover:-translate-y-px hover:shadow-raised",
                on ? "border-accent ring-4 ring-accent/15" : "border-line hover:border-line-strong")}>
              <span aria-hidden className="absolute inset-x-0 top-0 h-1" style={{ background: SEV_VAR[s] }} />
              <div className="flex items-center justify-between"><SeverityBadge severity={s} size="md" />{on && <span className="text-xs font-medium text-accent-text">Filtering</span>}</div>
              {loading && !data ? <Skeleton className="mt-5 h-9 w-14" /> : <div className="mt-4 text-[36px] font-semibold leading-none tracking-[-0.03em] text-ink">{n}</div>}
              <div className="mt-3 text-[13px] text-muted">{TILE_HINT[s]}</div>
              <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-surface-3">
                <div className="h-full rounded-full transition-[width] duration-500" style={{ width: `${all.length ? (n / all.length) * 100 : 0}%`, background: SEV_VAR[s] }} />
              </div>
            </button>
          );
        })}
      </section>

      <div className="mb-5 flex flex-wrap items-center gap-3">
        <SegmentedControl label="Triage status" value={status || "all"} onChange={(v) => setStatus(v === "all" ? "" : v)}
          options={[{ key: "all", label: `All ${statusCount("")}` }, ...FINDING_STATUS.map((s) => ({ key: s.value, label: `${s.label} ${statusCount(s.value)}` }))]} />
        {filtered && <Button size="sm" variant="ghost" icon={<FilterX />} onClick={reset}>Reset filters</Button>}
      </div>

      <Card pad={false}>
        {!loading && all.length === 0 ? (
          <EmptyState title="No findings" icon={<ShieldCheck />}>No detection rule fired for this analysis.</EmptyState>
        ) : (
          <DataTable<Finding>
            rows={rows} loading={loading && !data} rowKey={(f) => f.id} onRowClick={setOpen} pageSize={25} searchPlaceholder="Search findings or rule IDs..."
            initialSort={{ key: "severity", dir: "asc" }} empty="No findings match these filters."
            rowAccent={(f) => SEV_VAR[f.severity]}
            toolbar={<>
              <Select label="Process" value={proc} onChange={setProc} className="w-44"><option value="">All processes</option>{opts.procs.map((p) => <option key={p}>{p}</option>)}</Select>
              <Select label="Category" value={cat} onChange={setCat} className="w-48"><option value="">All categories</option>{opts.cats.map((c) => <option key={c} value={c}>{CATEGORY_LABEL[c] ?? c}</option>)}</Select>
              <Select label="Minimum confidence" value={minConf} onChange={setMinConf} className="w-44">
                <option value="0">Any confidence</option><option value="0.5">Medium and above</option><option value="0.75">High only</option>
              </Select>
            </>}
            columns={[
              { key: "severity", header: "Severity", sortValue: (f) => sevRank(f.severity), render: (f) => <SeverityBadge severity={f.severity} /> },
              { key: "title", header: "Finding", render: (f) => (
                <div className="min-w-[240px] max-w-[460px]">
                  <div className="font-medium leading-snug text-ink">{f.title}</div>
                  <div className="mt-1 font-mono text-[11px] text-faint">{f.rule_id}</div>
                </div>) },
              { key: "process_name", header: "Process", render: (f) => f.pid != null ? (
                <Link onClick={(e) => e.stopPropagation()} className="whitespace-nowrap font-medium text-ink-2 hover:text-accent-text hover:underline" to={`/analysis/${jobId}/processes/${f.pid}`}>
                  {f.process_name} <span className="font-mono text-[13px] font-normal text-muted">{f.pid}</span>
                </Link>) : <span className="text-faint">System-wide</span> },
              { key: "evidence", header: "Evidence", sortValue: (f) => f.evidence.length, render: (f) => (
                <span className="flex items-center gap-2 whitespace-nowrap">{f.evidence[0] && <SourceTag source={f.evidence[0].source} />}<span className="text-xs text-muted">{f.evidence.length} item{f.evidence.length === 1 ? "" : "s"}</span></span>) },
              { key: "confidence", header: "Confidence", render: (f) => <ConfidenceMeter value={f.confidence} showValue={false} /> },
              { key: "status", header: "Status", render: (f) => (
                <span onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}>
                  <Select label={`Status of ${f.title}`} value={f.status} onChange={(v) => updateStatus(f, v)} className="w-40 [&_select]:h-9 [&_select]:text-[13px]">
                    {FINDING_STATUS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
                  </Select>
                </span>) },
            ]}
          />
        )}
      </Card>

      <Drawer open={!!open} onClose={closeDrawer} title={open && <span>{open.title}</span>} subtitle={open && `F-${open.id} · ${CATEGORY_LABEL[open.category] ?? open.category}`}
        footer={open && <>
          <Select label="Finding status" value={open.status} onChange={(v) => updateStatus(open, v)} className="mr-auto w-44">
            {FINDING_STATUS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
          </Select>
          {open.pid != null && <Button to={`/analysis/${jobId}/processes/${open.pid}`}>Open process</Button>}
        </>}>
        {open && <ExplanationPanel finding={open} />}
      </Drawer>
    </>
  );
}
