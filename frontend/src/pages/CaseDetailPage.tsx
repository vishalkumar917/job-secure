import { ArrowRight, CheckCircle2, HardDrive, Lock, LockOpen, Play, ShieldCheck, Upload, XCircle } from "lucide-react";
import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Page } from "../components/layout/AppLayout";
import { useCrumbs } from "../components/layout/crumbs";
import {
  Badge, Button, Card, ConfirmDialog, CopyButton, cx, DemoTag, EmptyState, ErrorState, KeyValue, Modal, Mono, Notice, PageHeader, RiskBadge,
  Skeleton, SkeletonCards, StatusPill, Switch,
} from "../components/ui";
import { useApi, usePolling } from "../hooks/useApi";
import { useNow } from "../hooks/useShell";
import { useToast } from "../hooks/useToast";
import { api } from "../services/api";
import { fmtBytes, fmtRelative, fmtTime, titleCase } from "../services/format";
import type { ImageInfo, Job } from "../types";

function Integrity({ j }: { j: Job }) {
  if (j.hash_verified_before == null) return <span className="text-faint">-</span>;
  const ok = j.hash_verified_before && j.hash_verified_after !== false;
  return (
    <span className={cx("inline-flex items-center gap-1.5 text-[13px]", ok ? "text-good-text" : "text-sev-critical-text")}>
      {ok ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}{ok ? "Verified" : "Mismatch"}
    </span>
  );
}

export default function CaseDetailPage() {
  const caseId = Number(useParams().caseId);
  const nav = useNavigate();
  const toast = useToast();
  const now = useNow();
  const { data, error, loading, reload } = useApi(() => api.case(caseId), [caseId]);
  const custody = useApi(() => api.custody(caseId), [caseId]);
  const [confirmClose, setConfirmClose] = useState(false);
  const [startFor, setStartFor] = useState<ImageInfo | null>(null);
  const [useYara, setUseYara] = useState(true);
  const [verifying, setVerifying] = useState<number | null>(null);
  useCrumbs([{ label: "Investigations", to: "/investigations" }, { label: data?.case_number ?? "Investigation" }]);
  usePolling(() => { reload(); custody.reload(); }, 4000, !!data?.jobs.some((j) => j.status === "running" || j.status === "queued"));

  if (loading && !data) {
    return <Page><Skeleton className="h-4 w-40" /><Skeleton className="mt-4 h-9 w-2/3" /><SkeletonCards count={3} className="mt-10 xl:grid-cols-3" /></Page>;
  }
  if (error || !data) {
    return <Page><ErrorState title="Investigation unavailable" message={error ?? "Not found"} onRetry={reload} actions={<Button to="/investigations">All investigations</Button>} /></Page>;
  }

  const verify = async (img: ImageInfo) => {
    setVerifying(img.id);
    try {
      const r = await api.verifyImage(img.id);
      if (r.match) toast({ tone: "success", title: "Integrity verified", description: `SHA-256 of ${img.original_filename} matches the intake hash.` });
      else toast({ tone: "error", title: "Hash mismatch", description: `${img.original_filename} has changed since intake.` });
      custody.reload();
    } catch (e) {
      toast({ tone: "error", title: "Verification failed", description: (e as Error).message });
    } finally {
      setVerifying(null);
    }
  };

  const start = async () => {
    if (!startFor) return;
    try {
      const job = await api.startAnalysis(startFor.id, useYara);
      toast({ tone: "info", title: "Analysis started", description: startFor.original_filename });
      nav(`/analysis/${job.id}/progress`);
    } catch (e) {
      toast({ tone: "error", title: "Could not start analysis", description: (e as Error).message });
      setStartFor(null);
    }
  };

  const toggleCase = async () => {
    await api.updateCase(caseId, { status: data.status === "open" ? "closed" : "open" });
    toast({ tone: "success", title: data.status === "open" ? "Case closed" : "Case re-opened" });
    setConfirmClose(false);
    reload();
    custody.reload();
  };

  const open = data.status === "open";
  return (
    <Page>
      {data.is_demo && <Notice tone="danger" className="mb-8" title="Demo data - not real forensic evidence">This case was created from the synthetic demonstration dataset.</Notice>}
      <PageHeader
        eyebrow={<span className="inline-flex items-center gap-2.5 font-mono normal-case tracking-normal">{data.case_number}{data.is_demo && <DemoTag />}</span>}
        title={data.title}
        subtitle={data.description || "No description provided."}
        meta={<>
          <StatusPill status={data.status} />
          <span>Investigator: <span className="text-ink-2">{data.investigator?.full_name || data.investigator?.username || "-"}</span></span>
          <span title={fmtTime(data.created_at)}>Opened {fmtRelative(data.created_at, now)}</span>
          <span>{data.images.length} image{data.images.length === 1 ? "" : "s"} · {data.jobs.length} analys{data.jobs.length === 1 ? "is" : "es"}</span>
        </>}
        actions={<>
          <Button onClick={() => setConfirmClose(true)} icon={open ? <Lock /> : <LockOpen />}>{open ? "Close case" : "Re-open case"}</Button>
          {open && !data.is_demo && <Button variant="primary" to={`/investigations/${caseId}/upload`} icon={<Upload />}>Upload memory image</Button>}
        </>} />

      <div className="grid gap-6 xl:grid-cols-12">
        <div className="space-y-6 xl:col-span-8">
          {data.images.length === 0 ? (
            <Card>
              <EmptyState title="No evidence uploaded" icon={<HardDrive />}
                action={open && <Button variant="primary" to={`/investigations/${caseId}/upload`} icon={<Upload />}>Upload memory image</Button>}>
                Upload a .raw, .mem, .dmp or .vmem memory image to begin the analysis.
              </EmptyState>
            </Card>
          ) : data.images.map((img) => {
            const jobs = data.jobs.filter((j) => j.image_id === img.id).sort((a, b) => b.id - a.id);
            const active = jobs.some((j) => j.status === "running" || j.status === "queued");
            const os = img.os_info;
            return (
              <Card key={img.id} icon={<HardDrive />} title={<span className="break-all">{img.original_filename}</span>}
                subtitle={`${fmtBytes(img.size_bytes)} · ${img.format_hint} · uploaded ${fmtRelative(img.uploaded_at, now)}`}
                actions={<>
                  <Button size="sm" onClick={() => verify(img)} disabled={verifying === img.id} icon={<ShieldCheck />}>{verifying === img.id ? "Verifying..." : "Verify hash"}</Button>
                  <Button size="sm" variant="primary" disabled={active} onClick={() => setStartFor(img)} icon={<Play />}>{jobs.length ? "Re-analyse" : "Start analysis"}</Button>
                </>}>
                <div className="rounded-xl border border-line bg-surface-2/50 px-4 py-3">
                  <div className="text-xs font-medium uppercase tracking-[0.06em] text-muted">SHA-256 (intake)</div>
                  <div className="mt-1 flex flex-wrap items-center gap-2"><Mono className="text-ink">{img.sha256}</Mono><CopyButton text={img.sha256} compact /></div>
                </div>
                <div className="mt-6">
                  <KeyValue cols={2} rows={[
                    ["Operating system", os?.os_name ? `${os.os_name} ${os.architecture ?? ""}` : <span className="text-muted">Not yet identified</span>],
                    ["Build / confidence", os?.os_name ? `${os.build ?? "?"} · ${os.confidence ?? "low"} confidence` : "-"],
                    ["Uploaded (UTC)", fmtTime(img.uploaded_at)],
                    ["Intake validation", <span key="v" className="text-ink-2">{img.validation_notes.join(" ") || "-"}</span>],
                  ]} />
                </div>
                <div className="mt-7">
                  <div className="mb-3 text-[13px] font-semibold text-ink">Analyses</div>
                  {jobs.length === 0 ? <p className="text-sm text-muted">This image has not been analysed yet.</p> : (
                    <ul className="divide-y divide-line overflow-hidden rounded-xl border border-line">
                      {jobs.map((j) => (
                        <li key={j.id}>
                          <button type="button" onClick={() => nav(j.status.startsWith("completed") ? `/analysis/${j.id}` : `/analysis/${j.id}/progress`)}
                            className="group flex w-full flex-wrap items-center gap-x-6 gap-y-2 px-4 py-4 text-left transition-colors hover:bg-surface-2/70">
                            <span className="w-24 font-mono text-[13px] font-medium text-ink">#{j.id}</span>
                            <StatusPill status={j.status} />
                            <RiskBadge score={j.overall_risk_score} band={j.overall_risk_band} />
                            <Integrity j={j} />
                            <span className="ml-auto text-[13px] text-muted" title={fmtTime(j.started_at)}>{fmtRelative(j.started_at ?? j.created_at, now)}</span>
                            <ArrowRight className="h-4 w-4 text-faint transition-transform group-hover:translate-x-0.5 group-hover:text-ink" />
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </Card>
            );
          })}
        </div>

        <Card className="xl:col-span-4 xl:self-start" title="Chain of custody" subtitle="Append-only record of every evidence action">
          {custody.loading && !custody.data ? <Skeleton className="h-64" /> : !custody.data?.length ? <EmptyState compact title="No events" /> : (
            <ol className="relative space-y-6 pl-6 before:absolute before:bottom-2 before:left-[5px] before:top-2 before:w-px before:bg-line">
              {custody.data.map((e, i) => (
                <li key={e.id} className="relative">
                  <span className={cx("absolute -left-6 top-1.5 h-[11px] w-[11px] rounded-full border-2 border-surface", i === custody.data!.length - 1 ? "bg-accent" : "bg-line-strong")} />
                  <div className="text-sm font-medium text-ink">{titleCase(e.action)}</div>
                  <div className="mt-0.5 text-xs text-muted">{fmtTime(e.timestamp)} · {e.actor}</div>
                  {e.details && <p className="mt-1.5 text-[13px] leading-relaxed text-ink-2">{e.details}</p>}
                  {e.sha256 && <div className="mt-1.5 flex items-center gap-1"><Badge className="font-mono font-medium">{e.sha256.slice(0, 20)}…</Badge><CopyButton text={e.sha256} compact /></div>}
                </li>
              ))}
            </ol>
          )}
        </Card>
      </div>

      <ConfirmDialog open={confirmClose} title={open ? "Close this case?" : "Re-open this case?"}
        onCancel={() => setConfirmClose(false)} onConfirm={toggleCase} confirmLabel={open ? "Close case" : "Re-open"}>
        {open ? "Closed cases cannot receive new evidence. The action is recorded in the chain of custody." : "The case will accept new evidence again."}
      </ConfirmDialog>
      <Modal open={!!startFor} onClose={() => setStartFor(null)} title="Start analysis"
        description={startFor ? `Run the staged Volatility 3 pipeline against ${startFor.original_filename}.` : undefined}
        footer={<><Button onClick={() => setStartFor(null)}>Cancel</Button><Button variant="primary" onClick={start} icon={<Play />}>Start analysis</Button></>}>
        <p>The evidence is re-hashed before and after analysis and is never modified.</p>
        <div className="mt-5"><Switch checked={useYara} onChange={setUseYara} label="Include YARA scanning" description="vadyarascan with enabled rule files on triaged processes" /></div>
      </Modal>
    </Page>
  );
}
