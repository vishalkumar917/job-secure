import { ArrowRight, Globe, Network as NetIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { NetworkChart } from "../components/charts";
import { useAnalysis, useAnalysisCrumbs } from "../components/layout/AppLayout";
import { Badge, Card, cx, DataTable, EmptyState, ErrorState, Mono, Notice, PageHeader, SectionHeader, SegmentedControl, Skeleton, SkeletonChart } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { fmtTime } from "../services/format";
import type { Connection } from "../types";

const SERVICE: Record<number, string> = {
  20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC", 137: "NetBIOS", 138: "NetBIOS",
  139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 636: "LDAPS", 993: "IMAPS", 1433: "MSSQL", 3389: "RDP",
  4444: "Metasploit default", 5355: "LLMNR", 5985: "WinRM", 5986: "WinRM", 8080: "HTTP-alt", 8443: "HTTPS-alt",
};
const svc = (port: number | null) => (port == null ? "" : SERVICE[port] ?? "");

type Filter = "all" | "suspicious" | "external" | "listening";

export default function NetworkPage() {
  const { jobId } = useAnalysis();
  useAnalysisCrumbs({ label: "Network" });
  const net = useApi(() => api.network(jobId), [jobId]);
  const [filter, setFilter] = useState<Filter>("all");
  const all = net.data ?? [];
  const rows = all.filter((c) => filter === "all" || (filter === "suspicious" ? c.is_suspicious : filter === "external" ? c.is_external : c.state === "LISTENING"));
  const suspicious = all.filter((c) => c.is_suspicious);

  const endpoints = useMemo(() => {
    const m = new Map<string, { addr: string; count: number; external: boolean; flagged: boolean; procs: Set<string>; ports: Set<number> }>();
    all.forEach((c) => {
      if (!c.foreign_addr || ["0.0.0.0", "::", "*", "127.0.0.1", "::1"].includes(c.foreign_addr)) return;
      const r = m.get(c.foreign_addr) ?? { addr: c.foreign_addr, count: 0, external: c.is_external, flagged: false, procs: new Set(), ports: new Set() };
      r.count++;
      r.flagged ||= c.is_suspicious;
      if (c.owner) r.procs.add(`${c.owner} (${c.pid})`);
      if (c.foreign_port != null) r.ports.add(c.foreign_port);
      m.set(c.foreign_addr, r);
    });
    return [...m.values()].sort((a, b) => Number(b.flagged) - Number(a.flagged) || b.count - a.count).slice(0, 8);
  }, [all]);
  const maxCount = Math.max(1, ...endpoints.map((e) => e.count));

  const stats = [
    { label: "Connections", value: all.length },
    { label: "External", value: all.filter((c) => c.is_external).length },
    { label: "Unique remote IPs", value: new Set(all.map((c) => c.foreign_addr).filter((a) => a && !["0.0.0.0", "::", "*"].includes(a))).size },
    { label: "Listening", value: all.filter((c) => c.state === "LISTENING").length },
    { label: "Owning processes", value: new Set(all.map((c) => c.pid)).size },
    { label: "Suspicious", value: suspicious.length, warn: true },
  ];

  if (net.error) return <ErrorState title="Network evidence unavailable" message={net.error} onRetry={net.reload} />;

  return (
    <>
      <PageHeader title="Network Forensics" subtitle="TCP/UDP endpoints recovered by netscan with their owning processes, evaluated against configurable heuristics (rules/network.yaml)." />
      <Notice className="mb-8">Remote addresses are <b>not</b> asserted to be malicious. Flags are heuristics (ports, process/network mismatch, watchlist) - enrich addresses with threat intelligence before drawing conclusions.</Notice>

      <Card className="mb-10">
        {net.loading && !net.data ? <Skeleton className="h-14" /> : (
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
        <SectionHeader title="Suspicious connections" subtitle="Connections matching at least one network heuristic" />
        {net.loading && !net.data ? <Skeleton className="h-28 rounded-2xl" /> : suspicious.length === 0 ? (
          <Card><EmptyState compact title="No suspicious connections" icon={<NetIcon />}>No endpoint matched the network heuristics.</EmptyState></Card>
        ) : (
          <div className="space-y-3">
            {suspicious.map((c) => (
              <div key={c.id} className="relative flex flex-col gap-4 rounded-2xl border border-line bg-surface p-5 shadow-card md:flex-row md:items-center md:gap-6 md:p-6">
                <span aria-hidden className="absolute inset-y-5 left-0 w-[3px] rounded-r-full bg-sev-high" />
                <div className="flex min-w-0 flex-1 flex-wrap items-center gap-3">
                  <Link to={`/analysis/${jobId}/processes/${c.pid}`} className="rounded-xl border border-line bg-surface-2/60 px-3.5 py-2 transition-colors hover:border-line-strong">
                    <div className="text-sm font-semibold text-ink">{c.owner ?? "unknown"}</div>
                    <div className="font-mono text-xs text-muted">PID {c.pid ?? "?"}</div>
                  </Link>
                  <div className="flex items-center gap-2 text-faint"><span className="hidden h-px w-8 bg-line-strong sm:block" /><ArrowRight className="h-4 w-4" /></div>
                  <div className="rounded-xl border border-sev-high/30 bg-sev-high/[0.06] px-3.5 py-2">
                    <div className="font-mono text-sm font-semibold text-ink">{c.foreign_addr}:{c.foreign_port}</div>
                    <div className="text-xs text-muted">{c.protocol}{svc(c.foreign_port) && ` · ${svc(c.foreign_port)}`} · {c.state ?? "-"}</div>
                  </div>
                </div>
                <div className="min-w-0 md:max-w-md">
                  <Badge tone="danger">Suspicious</Badge>
                  <p className="mt-2 text-[13px] leading-relaxed text-ink-2">{c.reason}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <div className="mb-12 grid gap-6 lg:grid-cols-12">
        <Card className="lg:col-span-5" title="Top remote endpoints" subtitle="By number of connections; flagged endpoints first">
          {net.loading && !net.data ? <SkeletonChart height={200} /> : endpoints.length === 0 ? <EmptyState compact title="No remote endpoints" icon={<Globe />} /> : (
            <ul className="space-y-4">
              {endpoints.map((e) => (
                <li key={e.addr}>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="flex items-center gap-2"><Mono className={cx("text-[13px]", e.flagged ? "font-semibold text-ink" : "text-ink-2")}>{e.addr}</Mono>
                      {e.flagged ? <Badge tone="danger">Flagged</Badge> : e.external ? <Badge>External</Badge> : <Badge>Internal</Badge>}</span>
                    <span className="text-[13px] font-semibold tabular text-ink">{e.count}</span>
                  </div>
                  <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-3">
                    <div className="h-full rounded-full" style={{ width: `${(e.count / maxCount) * 100}%`, background: e.flagged ? "var(--color-sev-high)" : "var(--color-accent)" }} />
                  </div>
                  <div className="mt-1.5 truncate text-xs text-muted">{[...e.procs].join(", ")} · port{e.ports.size === 1 ? "" : "s"} {[...e.ports].slice(0, 4).join(", ")}</div>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card className="lg:col-span-7" title="Connections by process" subtitle="Internal / local vs external endpoints">
          {net.data ? <NetworkChart connections={all} /> : <SkeletonChart />}
        </Card>
      </div>

      <SectionHeader title="All connections" />
      <Card pad={false}>
        <DataTable<Connection>
          rows={rows} loading={net.loading && !net.data} rowKey={(c) => c.id} initialSort={{ key: "is_suspicious", dir: "desc" }} searchPlaceholder="Search address, port, process..."
          rowAccent={(c) => (c.is_suspicious ? "var(--color-sev-high)" : undefined)} empty="No connections match this filter."
          toolbar={<SegmentedControl label="Connection filter" value={filter} onChange={setFilter} options={[
            { key: "all", label: "All" }, { key: "suspicious", label: "Suspicious" }, { key: "external", label: "External" }, { key: "listening", label: "Listening" },
          ]} />}
          columns={[
            { key: "owner", header: "Process", render: (c) => c.pid != null ? (
              <Link onClick={(e) => e.stopPropagation()} className="font-medium text-ink hover:text-accent-text hover:underline" to={`/analysis/${jobId}/processes/${c.pid}`}>
                {c.owner} <span className="font-mono text-[13px] font-normal text-muted">{c.pid}</span>
              </Link>) : c.owner },
            { key: "protocol", header: "Protocol", render: (c) => <span className="font-mono text-[13px]">{c.protocol}</span> },
            { key: "local", header: "Local", sortValue: (c) => `${c.local_addr}:${c.local_port}`, render: (c) => <Mono nowrap>{c.local_addr}:{c.local_port}</Mono> },
            { key: "foreign", header: "Remote", sortValue: (c) => `${c.foreign_addr}:${c.foreign_port}`, render: (c) => (
              <span className="whitespace-nowrap"><Mono nowrap className={c.is_suspicious ? "font-semibold text-ink" : ""}>{c.foreign_addr}:{c.foreign_port}</Mono>
                {svc(c.foreign_port) && <span className="ml-2 text-xs text-muted">{svc(c.foreign_port)}</span>}</span>) },
            { key: "state", header: "State", render: (c) => <span className="text-[13px]">{c.state ?? "-"}</span> },
            { key: "is_external", header: "Scope", sortValue: (c) => Number(c.is_external), render: (c) => c.is_external ? <Badge tone="accent">External</Badge> : <Badge>Local</Badge> },
            { key: "created", header: "Created (UTC)", render: (c) => <span className="whitespace-nowrap text-[13px] text-muted">{fmtTime(c.created)}</span> },
            { key: "is_suspicious", header: "Why flagged", sortValue: (c) => Number(c.is_suspicious), render: (c) => c.reason ? <span className="line-clamp-2 max-w-xs text-[13px] text-sev-high-text">{c.reason}</span> : <span className="text-faint">-</span> },
          ]}
        />
      </Card>
    </>
  );
}
