import { Copy, Download, Eye, Fingerprint, Search, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAnalysis, useAnalysisCrumbs } from "../components/layout/AppLayout";
import { Badge, Button, Card, CopyButton, cx, DataTable, Drawer, EmptyState, ErrorState, KeyValue, Mono, PageHeader, Select, SourceTag, Switch, Tabs } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useToast } from "../hooks/useToast";
import { api, download } from "../services/api";
import { IOC_TYPE_LABEL } from "../services/format";
import type { IOC } from "../types";

type Cat = "all" | "ip" | "domain" | "url" | "hash" | "path" | "command" | "other";
const CAT_TYPES: Record<Exclude<Cat, "all" | "other">, string[]> = {
  ip: ["ipv4", "ipv6"], domain: ["domain"], url: ["url"], hash: ["md5", "sha1", "sha256"], path: ["file_path", "dll"], command: ["command"],
};
const catOf = (t: string): Cat => (Object.entries(CAT_TYPES).find(([, v]) => v.includes(t))?.[0] as Cat) ?? "other";
const CONF_TONE = { high: "danger", medium: "warning", low: "neutral" } as const;

/** Map an IOC source plugin to the view that holds the underlying evidence. */
function evidenceRoute(i: IOC, base: string): string {
  const s = i.source;
  if (s.includes("netscan")) return `${base}/network`;
  if (s.includes("yara") || s.includes("malfind") || s.includes("vad")) return `${base}/memory`;
  if (i.pid != null) return `${base}/processes/${i.pid}?tab=${s.includes("cmdline") || s.includes("PowerShell") ? "cmdline" : s.includes("dll") || s.includes("ldr") ? "modules" : "evidence"}`;
  return `${base}/findings`;
}

export default function IocExplorerPage() {
  const { jobId, job } = useAnalysis();
  useAnalysisCrumbs({ label: "IOCs" });
  const nav = useNavigate();
  const toast = useToast();
  const [params] = useSearchParams();
  const iocs = useApi(() => api.iocs(jobId), [jobId]);
  const [cat, setCat] = useState<Cat>("all");
  const [conf, setConf] = useState("");
  const [watchOnly, setWatchOnly] = useState(false);
  const [open, setOpen] = useState<IOC | null>(null);
  const base = `/analysis/${jobId}`;

  const all = iocs.data ?? [];
  const counts = useMemo(() => {
    const c: Record<Cat, number> = { all: all.length, ip: 0, domain: 0, url: 0, hash: 0, path: 0, command: 0, other: 0 };
    all.forEach((i) => c[catOf(i.ioc_type)]++);
    return c;
  }, [all]);
  const rows = all.filter((i) => (cat === "all" || catOf(i.ioc_type) === cat) && (!conf || i.confidence === conf) && (!watchOnly || i.watchlist_match));

  const exportAs = async (format: "csv" | "json") => {
    try {
      await download("/api/iocs/export", { analysis_id: jobId, format }, `iocs.${format}`);
      toast({ tone: "success", title: `IOCs exported as ${format.toUpperCase()}`, description: job.image.is_demo ? "Export is labelled as demo data." : undefined });
    } catch (e) {
      toast({ tone: "error", title: "Export failed", description: (e as Error).message });
    }
  };

  const tabs: { key: Cat; label: string }[] = [
    { key: "all", label: "All" }, { key: "ip", label: "IP Addresses" }, { key: "domain", label: "Domains" }, { key: "url", label: "URLs" },
    { key: "hash", label: "Hashes" }, { key: "path", label: "File Paths" }, { key: "command", label: "Commands" }, { key: "other", label: "Other" },
  ];

  return (
    <>
      <PageHeader title="IOC Explorer" subtitle="Indicators extracted automatically from command lines (including decoded PowerShell), network endpoints, modules, handles and YARA."
        actions={<>
          <Button onClick={() => exportAs("csv")} icon={<Download />}>Export CSV</Button>
          <Button onClick={() => exportAs("json")} icon={<Download />}>Export JSON</Button>
        </>} />

      <Tabs value={cat} onChange={setCat} tabs={tabs.filter((t) => t.key === "all" || counts[t.key] > 0).map((t) => ({ ...t, count: counts[t.key] }))} />

      {iocs.error ? <ErrorState title="IOCs unavailable" message={iocs.error} onRetry={iocs.reload} /> : (
        <Card pad={false}>
          {!iocs.loading && all.length === 0 ? (
            <EmptyState title="No indicators extracted" icon={<Fingerprint />}>No IOC was found in command lines, network endpoints, modules, handles or YARA matches.</EmptyState>
          ) : (
            <DataTable<IOC>
              rows={rows} loading={iocs.loading && !iocs.data} rowKey={(i) => i.id} pageSize={30} onRowClick={setOpen}
              initialSearch={params.get("q") ?? ""} searchPlaceholder="Search indicator, process, context..."
              initialSort={{ key: "confidence", dir: "asc" }} empty="No indicators match these filters."
              rowAccent={(i) => (i.watchlist_match ? "var(--color-sev-critical)" : undefined)}
              toolbar={<>
                <Select label="Confidence" value={conf} onChange={setConf} className="w-44">
                  <option value="">Any confidence</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
                </Select>
                <Switch checked={watchOnly} onChange={setWatchOnly} label={<span className="text-[13px]">Watchlist matches only</span>} />
              </>}
              columns={[
                { key: "value", header: "Indicator", render: (i) => (
                  <div className="flex min-w-[220px] max-w-[440px] items-start gap-2">
                    <Mono className={cx("line-clamp-2", i.watchlist_match ? "font-semibold text-ink" : "text-ink")} title={i.value}>{i.value}</Mono>
                    {i.watchlist_match && <Badge tone="danger" icon={<ShieldAlert />}>Watchlist</Badge>}
                  </div>) },
                { key: "ioc_type", header: "Type", render: (i) => <span className="whitespace-nowrap text-[13px] text-ink-2">{IOC_TYPE_LABEL[i.ioc_type] ?? i.ioc_type}</span> },
                { key: "process_name", header: "Found in", render: (i) => i.pid != null ? <span className="whitespace-nowrap text-ink-2">{i.process_name} <span className="font-mono text-[13px] text-muted">{i.pid}</span></span> : <span className="text-faint">-</span> },
                { key: "source", header: "Source", render: (i) => <SourceTag source={i.source} /> },
                { key: "confidence", header: "Confidence", sortValue: (i) => ({ high: 0, medium: 1, low: 2 })[i.confidence],
                  render: (i) => <Badge tone={CONF_TONE[i.confidence]} className="capitalize">{i.confidence}</Badge> },
                { key: "actions", header: "", sortable: false, align: "right", render: (i) => <CopyButton text={i.value} compact /> },
              ]}
            />
          )}
        </Card>
      )}

      <Drawer open={!!open} onClose={() => setOpen(null)} title="Indicator of compromise" subtitle={open && `${IOC_TYPE_LABEL[open.ioc_type] ?? open.ioc_type} · ${open.source}`}
        footer={open && <>
          <Button icon={<Copy />} onClick={() => { navigator.clipboard?.writeText(open.value); toast({ tone: "success", title: "Indicator copied" }); }}>Copy</Button>
          <Button icon={<Eye />} onClick={() => nav(evidenceRoute(open, base))}>View evidence</Button>
          {open.pid != null && <Button variant="primary" icon={<Search />} onClick={() => nav(`${base}/processes/${open.pid}`)}>Investigate process</Button>}
        </>}>
        {open && (
          <div className="space-y-7">
            <div className="rounded-xl border border-line bg-surface-2/60 p-5">
              <Mono className="text-[15px] text-ink">{open.value}</Mono>
              {open.watchlist_match && <div className="mt-3"><Badge tone="danger" icon={<ShieldAlert />}>Matches the local threat-intelligence watchlist</Badge></div>}
            </div>
            <KeyValue cols={2} rows={[
              ["Type", IOC_TYPE_LABEL[open.ioc_type] ?? open.ioc_type],
              ["Confidence", <Badge key="c" tone={CONF_TONE[open.confidence]} className="capitalize">{open.confidence}</Badge>],
              ["Found in", open.pid != null ? `${open.process_name} (PID ${open.pid})` : "Not tied to a process"],
              ["Source", <SourceTag key="s" source={open.source} />],
            ]} />
            <div>
              <div className="mb-2 text-xs font-semibold uppercase tracking-[0.06em] text-muted">Context</div>
              <p className="text-sm leading-relaxed text-ink-2">{open.context || "No additional context recorded."}</p>
            </div>
            <p className="text-[13px] leading-relaxed text-muted">An indicator extracted from memory is a lead, not a verdict. Enrich it with threat intelligence before acting on it.</p>
          </div>
        )}
      </Drawer>
    </>
  );
}
