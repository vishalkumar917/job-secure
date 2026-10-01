import { FolderPlus } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { Page } from "../components/layout/AppLayout";
import { DataTable } from "../components/ui/DataTable";
import { Button, Card, ErrorState, Loading, PageHeader, StatusPill } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { fmtTime } from "../services/format";
import type { Case } from "../types";

export default function InvestigationsPage() {
  const nav = useNavigate();
  const { data, error, loading, reload } = useApi(() => api.cases(), []);
  return (
    <Page>
      <PageHeader title="Investigations" subtitle="Cases group memory images, analyses, reports and chain-of-custody records."
        actions={<Link to="/investigations/new"><Button variant="primary"><FolderPlus className="h-4 w-4" />New investigation</Button></Link>} />
      <Card>
        {loading && !data ? <Loading /> : error ? <ErrorState message={error} onRetry={reload} /> : (
          <DataTable<Case>
            rows={data ?? []}
            rowKey={(c) => c.id}
            onRowClick={(c) => nav(`/investigations/${c.id}`)}
            initialSort={{ key: "created_at", dir: "desc" }}
            empty="No investigations yet - create one to begin."
            columns={[
              { key: "case_number", header: "Case", render: (c) => <span className="font-medium text-ink">{c.case_number}</span> },
              { key: "title", header: "Title", render: (c) => <span>{c.is_demo && <span className="mr-1 rounded bg-sev-critical/20 px-1 text-[10px] font-bold text-[#f08a8a]">DEMO</span>}{c.title}</span> },
              { key: "investigator", header: "Investigator", sortValue: (c) => c.investigator?.username, render: (c) => c.investigator?.username ?? "-" },
              { key: "status", header: "Status", render: (c) => <StatusPill status={c.status} /> },
              { key: "created_at", header: "Opened", render: (c) => <span className="text-xs text-muted">{fmtTime(c.created_at)}</span> },
            ]}
          />
        )}
      </Card>
    </Page>
  );
}
