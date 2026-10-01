import { useState } from "react";
import { Link } from "react-router-dom";
import { useAnalysis } from "../components/layout/AppLayout";
import { NetworkChart } from "../components/charts";
import { DataTable } from "../components/ui/DataTable";
import { Card, ErrorState, Loading, Mono, Notice, PageHeader } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { fmtTime } from "../services/format";
import type { Connection } from "../types";

export default function NetworkPage() {
  const { jobId } = useAnalysis();
  const net = useApi(() => api.network(jobId), [jobId]);
  const [filter, setFilter] = useState<"all" | "suspicious" | "external" | "listening">("all");
  const rows = (net.data ?? []).filter((c) =>
    filter === "all" ? true : filter === "suspicious" ? c.is_suspicious : filter === "external" ? c.is_external : c.state === "LISTENING");

  return (
    <>
      <PageHeader title="Network forensics" subtitle="TCP/UDP endpoints recovered by netscan, with owning processes and configurable heuristics (rules/network.yaml)." />
      <div className="mb-4"><Notice>Remote addresses are <b>not</b> asserted to be malicious. Flags are heuristics (ports, process/network mismatch, watchlist); enrich addresses with threat intelligence before drawing conclusions.</Notice></div>
      <Card title="Connections by process" className="mb-4">{net.data ? <NetworkChart connections={net.data} /> : <Loading />}</Card>
      <Card>
        {net.loading && !net.data ? <Loading /> : net.error ? <ErrorState message={net.error} /> : (
          <DataTable<Connection>
            rows={rows} rowKey={(c) => c.id} initialSort={{ key: "is_suspicious", dir: "desc" }}
            rowClassName={(c) => (c.is_suspicious ? "bg-sev-high/10" : undefined)}
            toolbar={<select value={filter} onChange={(e) => setFilter(e.target.value as typeof filter)}
              className="rounded-lg border border-line bg-surface-2 px-2 py-2 text-sm text-ink" aria-label="Connection filter">
              <option value="all">All connections</option><option value="suspicious">Suspicious only</option>
              <option value="external">External only</option><option value="listening">Listening</option>
            </select>}
            columns={[
              { key: "protocol", header: "Proto" },
              { key: "local", header: "Local", sortValue: (c) => `${c.local_addr}:${c.local_port}`, render: (c) => <Mono>{c.local_addr}:{c.local_port}</Mono> },
              { key: "foreign", header: "Remote", sortValue: (c) => `${c.foreign_addr}:${c.foreign_port}`, render: (c) => <Mono>{c.foreign_addr}:{c.foreign_port}</Mono> },
              { key: "state", header: "State", render: (c) => c.state ?? "-" },
              { key: "pid", header: "PID", className: "tabular" },
              { key: "owner", header: "Process", render: (c) => c.pid != null ? <Link className="text-accent hover:underline" to={`/analysis/${jobId}/processes/${c.pid}`}>{c.owner}</Link> : c.owner },
              { key: "is_external", header: "Scope", sortValue: (c) => Number(c.is_external), render: (c) => c.is_external ? "external" : "local" },
              { key: "created", header: "Created (UTC)", render: (c) => <span className="whitespace-nowrap text-xs text-muted">{fmtTime(c.created)}</span> },
              { key: "is_suspicious", header: "Why flagged", sortValue: (c) => Number(c.is_suspicious), render: (c) => <span className="text-xs text-sev-high">{c.reason}</span> },
            ]}
          />
        )}
      </Card>
    </>
  );
}
