import { Download } from "lucide-react";
import { useState } from "react";
import { useAnalysis } from "../components/layout/AppLayout";
import { DataTable } from "../components/ui/DataTable";
import { Button, Card, CopyButton, cx, ErrorState, Loading, Mono, PageHeader } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api, download } from "../services/api";
import type { IOC } from "../types";

const CONF_CLS = { high: "text-sev-high", medium: "text-sev-medium", low: "text-muted" };

export default function IocExplorerPage() {
  const { jobId } = useAnalysis();
  const iocs = useApi(() => api.iocs(jobId), [jobId]);
  const [type, setType] = useState("");
  const [conf, setConf] = useState("");
  const types = [...new Set((iocs.data ?? []).map((i) => i.ioc_type))].sort();
  const rows = (iocs.data ?? []).filter((i) => (!type || i.ioc_type === type) && (!conf || i.confidence === conf));
  const sel = "rounded-lg border border-line bg-surface-2 px-2 py-2 text-sm text-ink";

  return (
    <>
      <PageHeader title="IOC explorer" subtitle="Indicators extracted automatically from command lines (including decoded PowerShell), network endpoints, suspicious modules, handles and YARA."
        actions={<>
          <Button onClick={() => download("/api/iocs/export", { analysis_id: jobId, format: "csv" }, "iocs.csv")}><Download className="h-4 w-4" />CSV</Button>
          <Button onClick={() => download("/api/iocs/export", { analysis_id: jobId, format: "json" }, "iocs.json")}><Download className="h-4 w-4" />JSON</Button>
        </>} />
      <Card>
        {iocs.loading && !iocs.data ? <Loading /> : iocs.error ? <ErrorState message={iocs.error} /> : (
          <DataTable<IOC>
            rows={rows} rowKey={(i) => i.id} pageSize={40}
            initialSort={{ key: "confidence", dir: "asc" }}
            toolbar={<>
              <select className={sel} value={type} onChange={(e) => setType(e.target.value)} aria-label="IOC type"><option value="">All types</option>{types.map((t) => <option key={t}>{t}</option>)}</select>
              <select className={sel} value={conf} onChange={(e) => setConf(e.target.value)} aria-label="Confidence"><option value="">Any confidence</option><option>high</option><option>medium</option><option>low</option></select>
            </>}
            columns={[
              { key: "ioc_type", header: "Type", render: (i) => <span className="rounded bg-surface-3 px-1.5 py-0.5 font-mono text-xs">{i.ioc_type}</span> },
              { key: "value", header: "Value", render: (i) => <div className="max-w-xl"><Mono className="text-ink">{i.value}</Mono> <CopyButton text={i.value} />{i.watchlist_match && <span className="ml-2 rounded bg-sev-critical/20 px-1 text-[10px] font-bold text-[#f08a8a]">WATCHLIST</span>}</div> },
              { key: "source", header: "Source", render: (i) => <span className="font-mono text-xs">{i.source}</span> },
              { key: "process_name", header: "Process", render: (i) => i.process_name ? `${i.process_name} (${i.pid})` : "-" },
              { key: "confidence", header: "Confidence", sortValue: (i) => ({ high: 0, medium: 1, low: 2 })[i.confidence],
                render: (i) => <span className={cx("font-medium capitalize", CONF_CLS[i.confidence])}>{i.confidence}</span> },
              { key: "context", header: "Context", render: (i) => <span className="text-xs text-muted">{i.context}</span> },
            ]}
          />
        )}
      </Card>
    </>
  );
}
