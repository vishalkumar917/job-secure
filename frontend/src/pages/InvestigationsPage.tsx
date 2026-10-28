import { FolderPlus, FolderSearch } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Page } from "../components/layout/AppLayout";
import { useCrumbs } from "../components/layout/crumbs";
import { Button, Card, DataTable, DemoTag, EmptyState, ErrorState, PageHeader, SegmentedControl, StatusPill } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useNow } from "../hooks/useShell";
import { api } from "../services/api";
import { fmtRelative, fmtTime } from "../services/format";
import type { Case } from "../types";

type Filter = "all" | "open" | "closed";

export default function InvestigationsPage() {
  useCrumbs([{ label: "Investigations" }]);
  const nav = useNavigate();
  const now = useNow();
  const { data, error, loading, reload } = useApi(() => api.cases(), []);
  const [filter, setFilter] = useState<Filter>("all");
  const all = data ?? [];
  const rows = all.filter((c) => filter === "all" || c.status === filter);
  const count = (s: Filter) => (s === "all" ? all.length : all.filter((c) => c.status === s).length);

  return (
    <Page>
      <PageHeader title="Investigations" subtitle="Cases group memory images, analyses, reports and their chain-of-custody record."
        actions={<Button variant="primary" to="/investigations/new" icon={<FolderPlus />}>New investigation</Button>} />

      {error ? <ErrorState title="Could not load investigations" message={error} onRetry={reload} /> : (
        <Card pad={false}>
          {!loading && all.length === 0 ? (
            <EmptyState title="No investigations yet" icon={<FolderSearch />}
              action={<Button variant="primary" to="/investigations/new" icon={<FolderPlus />}>Create investigation</Button>}>
              Create your first forensic investigation by uploading a Windows memory image.
            </EmptyState>
          ) : (
            <DataTable<Case>
              rows={rows} loading={loading && !data} rowKey={(c) => c.id} onRowClick={(c) => nav(`/investigations/${c.id}`)}
              initialSort={{ key: "created_at", dir: "desc" }} searchPlaceholder="Search cases..."
              empty="No investigations match this filter."
              toolbar={<SegmentedControl label="Case status" value={filter} onChange={setFilter} options={[
                { key: "all", label: `All ${count("all")}` }, { key: "open", label: `Open ${count("open")}` }, { key: "closed", label: `Closed ${count("closed")}` },
              ]} />}
              columns={[
                { key: "case_number", header: "Investigation", sortValue: (c) => `${c.case_number} ${c.title}`, render: (c) => (
                  <div className="min-w-0 py-0.5">
                    <div className="flex items-center gap-2.5">
                      <span className="font-mono text-[13px] font-medium text-ink">{c.case_number}</span>
                      {c.is_demo && <DemoTag />}
                    </div>
                    <div className="mt-1 max-w-xl truncate text-sm text-ink-2">{c.title}</div>
                  </div>) },
                { key: "investigator", header: "Investigator", sortValue: (c) => c.investigator?.username, render: (c) => c.investigator?.full_name || c.investigator?.username || "-" },
                { key: "status", header: "Status", render: (c) => <StatusPill status={c.status} /> },
                { key: "created_at", header: "Opened", render: (c) => <span className="whitespace-nowrap text-[13px] text-muted" title={fmtTime(c.created_at)}>{fmtRelative(c.created_at, now)}</span> },
                { key: "updated_at", header: "Last activity", render: (c) => <span className="whitespace-nowrap text-[13px] text-muted" title={fmtTime(c.updated_at)}>{fmtRelative(c.updated_at, now)}</span> },
              ]}
            />
          )}
        </Card>
      )}
    </Page>
  );
}
