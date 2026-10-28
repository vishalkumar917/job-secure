import { Activity, CalendarClock, Cpu, FileCode2, Fingerprint, LogOut, MemoryStick, Network, ScanLine, ShieldAlert, Terminal } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useAnalysis, useAnalysisCrumbs } from "../components/layout/AppLayout";
import {
  Badge, Button, Card, cx, Drawer, EmptyState, ErrorState, KeyValue, Mono, Notice, PageHeader, SearchInput, SegmentedControl, Select, SEV_VAR,
  SeverityBadge, Skeleton, SourceTag,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { fmtClock, fmtDate, fmtTime, titleCase } from "../services/format";
import type { TimelineEvent } from "../types";

const TYPE: Record<string, { label: string; icon: ReactNode }> = {
  process_created: { label: "Process created", icon: <Cpu /> },
  process_exited: { label: "Process exited", icon: <LogOut /> },
  network_connection: { label: "Network connection", icon: <Network /> },
  suspicious_network: { label: "Suspicious network connection", icon: <Network /> },
  module_loaded: { label: "Module loaded", icon: <FileCode2 /> },
  memory_injection_indicator: { label: "Executable memory region detected", icon: <MemoryStick /> },
  suspicious_command: { label: "Suspicious command", icon: <Terminal /> },
  yara_match: { label: "YARA match", icon: <ScanLine /> },
  ioc_match: { label: "IOC identified", icon: <Fingerprint /> },
  finding: { label: "Finding", icon: <ShieldAlert /> },
};
const typeOf = (t: string) => TYPE[t] ?? { label: titleCase(t), icon: <Activity /> };
const ORDER = ["info", "low", "medium", "high", "critical"];

function refRoute(e: TimelineEvent, base: string): string | null {
  const r = e.evidence_ref ?? "";
  if (r.startsWith("PROC:") && e.pid != null) return `${base}/processes/${e.pid}`;
  if (r.startsWith("NET")) return `${base}/network`;
  if (r.startsWith("MEM")) return `${base}/memory`;
  if (r.startsWith("F-") || r.startsWith("F:")) return `${base}/findings?f=${r.slice(2)}`;
  if (r.startsWith("MOD") && e.pid != null) return `${base}/processes/${e.pid}?tab=modules`;
  if (r.startsWith("YARA")) return `${base}/memory#yara`;
  if (r.startsWith("IOC")) return `${base}/iocs`;
  return e.pid != null ? `${base}/processes/${e.pid}` : null;
}

export default function TimelinePage() {
  const { jobId } = useAnalysis();
  useAnalysisCrumbs({ label: "Timeline" });
  const { data, error, loading, reload } = useApi(() => api.timeline(jobId), [jobId]);
  const [minSev, setMinSev] = useState("medium");
  const [type, setType] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<TimelineEvent | null>(null);
  const base = `/analysis/${jobId}`;

  const all = data ?? [];
  const types = useMemo(() => [...new Set(all.map((e) => e.event_type))].sort(), [all]);
  const needle = q.trim().toLowerCase();
  const rows = all.filter((e) => ORDER.indexOf(e.severity) >= ORDER.indexOf(minSev) && (!type || e.event_type === type)
    && (!needle || `${e.description} ${e.process_name ?? ""} ${e.pid ?? ""}`.toLowerCase().includes(needle)));
  const dated = rows.filter((r) => r.timestamp);
  const undated = rows.filter((r) => !r.timestamp);
  const days = useMemo(() => {
    const m = new Map<string, TimelineEvent[]>();
    dated.forEach((e) => m.set(fmtDate(e.timestamp), [...(m.get(fmtDate(e.timestamp)) ?? []), e]));
    return [...m.entries()];
  }, [dated]);

  if (error) return <ErrorState title="Timeline unavailable" message={error} onRetry={reload} />;

  return (
    <>
      <PageHeader title="Forensic Timeline" subtitle="Built only from timestamps present in memory structures - EPROCESS create/exit, TCP endpoint creation and module load time. All times UTC." />

      <div className="mb-6 flex flex-wrap items-center gap-3">
        <SegmentedControl label="Minimum severity" value={minSev} onChange={setMinSev} options={[
          { key: "info", label: "All events" }, { key: "low", label: "Low+" }, { key: "medium", label: "Medium+" }, { key: "high", label: "High+" },
        ]} />
        <Select label="Event type" value={type} onChange={setType} className="w-56">
          <option value="">All event types</option>{types.map((t) => <option key={t} value={t}>{typeOf(t).label}</option>)}
        </Select>
        <SearchInput value={q} onChange={setQ} placeholder="Search events..." className="w-full sm:w-64" />
        <span className="ml-auto text-[13px] tabular text-muted">{rows.length} of {all.length} events</span>
      </div>
      <Notice className="mb-8">Findings have no intrinsic timestamp: they are anchored to the owning process's creation time (labelled as such) or listed under "Timestamp unavailable".</Notice>

      {loading && !data ? (
        <Card><div className="space-y-6">{[0, 1, 2, 3, 4].map((i) => <div key={i} className="flex gap-6"><Skeleton className="h-4 w-16" /><Skeleton className="h-16 flex-1 rounded-xl" /></div>)}</div></Card>
      ) : rows.length === 0 ? (
        <Card><EmptyState title="No events at this filter" icon={<CalendarClock />} action={<Button onClick={() => { setMinSev("info"); setType(""); setQ(""); }}>Show all events</Button>}>Lower the minimum severity or clear the search.</EmptyState></Card>
      ) : (
        <div className="space-y-10">
          {days.map(([day, events]) => (
            <section key={day}>
              <h2 className="mb-5 flex items-center gap-3 text-sm font-semibold text-ink">
                <CalendarClock className="h-4 w-4 text-muted" />{day}
                <span className="text-xs font-normal text-muted">{events.length} event{events.length === 1 ? "" : "s"}</span>
              </h2>
              <ol className="relative">
                {events.map((e, i) => {
                  const t = typeOf(e.event_type);
                  const strong = ORDER.indexOf(e.severity) >= ORDER.indexOf("high");
                  return (
                    <li key={e.id} className="relative grid grid-cols-[64px_28px_1fr] gap-x-3 sm:grid-cols-[84px_32px_1fr] sm:gap-x-4">
                      <time className="pt-[18px] text-right font-mono text-[13px] tabular text-ink-2" dateTime={e.timestamp ?? undefined}>{fmtClock(e.timestamp)}</time>
                      <div className="relative flex justify-center">
                        {i < events.length - 1 && <span aria-hidden className="absolute bottom-0 top-8 w-px bg-line" />}
                        {i > 0 && <span aria-hidden className="absolute top-0 h-4 w-px bg-line" />}
                        <span className={cx("relative z-[1] mt-3.5 flex h-7 w-7 items-center justify-center rounded-full border-2 bg-surface [&_svg]:h-3.5 [&_svg]:w-3.5")}
                          style={{ borderColor: SEV_VAR[e.severity], color: e.severity === "info" ? "var(--color-muted)" : SEV_VAR[e.severity] }}>{t.icon}</span>
                      </div>
                      <button type="button" onClick={() => setOpen(e)}
                        className={cx("mb-3 min-w-0 rounded-xl border bg-surface px-5 py-4 text-left shadow-card transition-[border-color,box-shadow] duration-150 hover:border-line-strong hover:shadow-raised",
                          strong ? "border-line-strong" : "border-line")}>
                        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                          <span className="text-sm font-semibold text-ink">{t.label}</span>
                          {e.severity !== "info" && <SeverityBadge severity={e.severity} />}
                          {e.pid != null && <span className="text-[13px] text-muted">{e.process_name} <span className="font-mono">({e.pid})</span></span>}
                        </div>
                        <p className="mt-1.5 text-sm leading-relaxed text-ink-2">{e.description}</p>
                        <div className="mt-2 text-xs text-faint">Time source: {e.timestamp_source}</div>
                      </button>
                    </li>
                  );
                })}
              </ol>
            </section>
          ))}
          {undated.length > 0 && (
            <Card title="Timestamp unavailable" subtitle="Events and findings without a timestamp in memory">
              <ul className="divide-y divide-line">
                {undated.map((e) => (
                  <li key={e.id}>
                    <button type="button" onClick={() => setOpen(e)} className="flex w-full flex-wrap items-center gap-3 py-3.5 text-left hover:text-ink">
                      <SeverityBadge severity={e.severity} /><span className="text-sm text-ink-2">{e.description}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      )}

      <Drawer open={!!open} onClose={() => setOpen(null)} width="md" title={open && typeOf(open.event_type).label} subtitle={open?.timestamp ? fmtTime(open.timestamp) : "Timestamp unavailable"}
        footer={open && refRoute(open, base) && <Button variant="primary" to={refRoute(open, base)!}>Open evidence</Button>}>
        {open && (
          <div className="space-y-7">
            <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={open.severity} size="md" /><Badge>{open.event_type}</Badge></div>
            <p className="text-[15px] leading-relaxed text-ink">{open.description}</p>
            <KeyValue rows={[
              ["Timestamp (UTC)", open.timestamp ? fmtTime(open.timestamp) : "Unavailable"],
              ["Time source", <SourceTag key="s" source={open.timestamp_source} />],
              ["Process", open.pid != null ? <Link key="p" className="font-medium text-ink hover:text-accent-text hover:underline" to={`${base}/processes/${open.pid}`}>{open.process_name} (PID {open.pid})</Link> : "Not tied to a process"],
              ["Evidence reference", open.evidence_ref ? <Mono key="r">{open.evidence_ref}</Mono> : "None"],
            ]} />
          </div>
        )}
      </Drawer>
    </>
  );
}
