import { FolderPlus, HardDrive, Upload } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Page } from "../components/layout/AppLayout";
import { useCrumbs } from "../components/layout/crumbs";
import { Button, Card, CopyButton, DataTable, DemoTag, EmptyState, ErrorState, Modal, PageHeader, Select } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useNow } from "../hooks/useShell";
import { api } from "../services/api";
import { fmtBytes, fmtRelative, fmtTime } from "../services/format";
import type { ImageInfo } from "../types";

/** All memory images across investigations (GET /api/memory without a case filter). */
export default function MemoryImagesPage() {
  useCrumbs([{ label: "Memory Images" }]);
  const nav = useNavigate();
  const now = useNow();
  const images = useApi(() => api.images(), []);
  const cases = useApi(() => api.cases(), []);
  const [pickCase, setPickCase] = useState(false);
  const [target, setTarget] = useState("");
  const caseById = useMemo(() => new Map((cases.data ?? []).map((c) => [c.id, c])), [cases.data]);
  const openCases = (cases.data ?? []).filter((c) => c.status === "open" && !c.is_demo);
  const totalBytes = (images.data ?? []).reduce((s, i) => s + i.size_bytes, 0);

  return (
    <Page>
      <PageHeader title="Memory Images" subtitle="Every acquired memory image, its intake hash and the investigation it belongs to."
        meta={images.data && <span>{images.data.length} image{images.data.length === 1 ? "" : "s"} · {fmtBytes(totalBytes)} of evidence</span>}
        actions={<>
          <Button icon={<Upload />} onClick={() => { setTarget(String(openCases[0]?.id ?? "")); setPickCase(true); }} disabled={!openCases.length}>Upload to existing case</Button>
          <Button variant="primary" to="/investigations/new" icon={<FolderPlus />}>New investigation</Button>
        </>} />

      {images.error ? <ErrorState title="Could not load memory images" message={images.error} onRetry={images.reload} /> : (
        <Card pad={false}>
          {!images.loading && (images.data ?? []).length === 0 ? (
            <EmptyState title="No memory images yet" icon={<HardDrive />}
              action={<Button variant="primary" to="/investigations/new" icon={<FolderPlus />}>Create investigation</Button>}>
              Memory images are added to an investigation. Create one to upload your first Windows memory image.
            </EmptyState>
          ) : (
            <DataTable<ImageInfo>
              rows={images.data ?? []} loading={images.loading && !images.data} rowKey={(i) => i.id} searchPlaceholder="Search filename, hash, OS..."
              onRowClick={(i) => nav(`/investigations/${i.case_id}`)} initialSort={{ key: "uploaded_at", dir: "desc" }}
              columns={[
                { key: "original_filename", header: "Image", render: (i) => (
                  <div className="flex min-w-0 items-center gap-3">
                    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-muted"><HardDrive className="h-4 w-4" /></span>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2"><span className="max-w-[320px] truncate font-medium text-ink">{i.original_filename}</span>{i.is_demo && <DemoTag />}</div>
                      <div className="mt-0.5 text-[13px] text-muted">{fmtBytes(i.size_bytes)} · {i.format_hint}</div>
                    </div>
                  </div>) },
                { key: "case", header: "Investigation", sortValue: (i) => caseById.get(i.case_id)?.case_number,
                  render: (i) => <span className="font-mono text-[13px] text-ink-2">{caseById.get(i.case_id)?.case_number ?? `#${i.case_id}`}</span> },
                { key: "sha256", header: "SHA-256", render: (i) => (
                  <span className="inline-flex items-center gap-1 font-mono text-xs text-muted" title={i.sha256}>{i.sha256.slice(0, 16)}…<CopyButton text={i.sha256} compact /></span>) },
                { key: "os", header: "Operating system", sortValue: (i) => i.os_info?.os_name ?? "",
                  render: (i) => i.os_info?.os_name ? <span className="text-ink-2">{i.os_info.os_name} <span className="text-muted">{i.os_info.architecture}</span></span> : <span className="text-faint">Not identified</span> },
                { key: "uploaded_at", header: "Uploaded", render: (i) => <span className="whitespace-nowrap text-[13px] text-muted" title={fmtTime(i.uploaded_at)}>{fmtRelative(i.uploaded_at, now)}</span> },
              ]}
            />
          )}
        </Card>
      )}

      <Modal open={pickCase} onClose={() => setPickCase(false)} title="Upload to an existing investigation"
        description="Evidence is always attached to a case so its chain of custody is complete."
        footer={<><Button onClick={() => setPickCase(false)}>Cancel</Button><Button variant="primary" disabled={!target} onClick={() => nav(`/investigations/${target}/upload`)}>Continue</Button></>}>
        <Select label="Investigation" value={target} onChange={setTarget} className="w-full">
          {openCases.map((c) => <option key={c.id} value={c.id}>{c.case_number} - {c.title}</option>)}
        </Select>
      </Modal>
    </Page>
  );
}
