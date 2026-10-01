import { Lock, Play, ShieldCheck, Upload } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Page } from "../components/layout/AppLayout";
import { Button, Card, ConfirmDialog, CopyButton, EmptyState, ErrorState, KeyValue, Loading, Mono, Notice, PageHeader, RiskBadge, StatusPill } from "../components/ui";
import { useApi, usePolling } from "../hooks/useApi";
import { api } from "../services/api";
import { fmtBytes, fmtTime } from "../services/format";
import type { ImageInfo } from "../types";

export default function CaseDetailPage() {
  const caseId = Number(useParams().caseId);
  const nav = useNavigate();
  const { data, error, loading, reload } = useApi(() => api.case(caseId), [caseId]);
  const custody = useApi(() => api.custody(caseId), [caseId]);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger" | "warn"; text: string } | null>(null);
  const [confirmClose, setConfirmClose] = useState(false);
  const [startFor, setStartFor] = useState<ImageInfo | null>(null);
  const [useYara, setUseYara] = useState(true);
  usePolling(() => { reload(); custody.reload(); }, 4000, !!data?.jobs.some((j) => j.status === "running" || j.status === "queued"));

  if (loading && !data) return <Page><Loading /></Page>;
  if (error || !data) return <Page><ErrorState message={error ?? "Not found"} onRetry={reload} /></Page>;

  const verify = async (img: ImageInfo) => {
    try {
      const r = await api.verifyImage(img.id);
      setMsg(r.match ? { tone: "ok", text: `Integrity verified: SHA-256 of ${img.original_filename} matches the intake hash.` }
        : { tone: "danger", text: `HASH MISMATCH for ${img.original_filename}: evidence has changed since intake.` });
      custody.reload();
    } catch (e) {
      setMsg({ tone: "danger", text: (e as Error).message });
    }
  };

  const start = async () => {
    if (!startFor) return;
    try {
      const job = await api.startAnalysis(startFor.id, useYara);
      nav(`/analysis/${job.id}/progress`);
    } catch (e) {
      setMsg({ tone: "danger", text: (e as Error).message });
      setStartFor(null);
    }
  };

  const closeCase = async () => {
    await api.updateCase(caseId, { status: data.status === "open" ? "closed" : "open" });
    setConfirmClose(false);
    reload();
    custody.reload();
  };

  return (
    <Page>
      {data.is_demo && <div className="mb-4"><Notice tone="danger"><b>DEMO DATA - NOT REAL FORENSIC EVIDENCE.</b> This case was created from the synthetic demonstration dataset.</Notice></div>}
      <PageHeader title={<span>{data.case_number} <span className="text-ink-2">- {data.title}</span></span>}
        subtitle={data.description || "No description"}
        actions={<>
          {data.status === "open" && !data.is_demo && <Link to={`/investigations/${caseId}/upload`}><Button variant="primary"><Upload className="h-4 w-4" />Upload memory image</Button></Link>}
          <Button onClick={() => setConfirmClose(true)}><Lock className="h-4 w-4" />{data.status === "open" ? "Close case" : "Re-open case"}</Button>
        </>} />
      {msg && <div className="mb-4"><Notice tone={msg.tone}>{msg.text}</Notice></div>}

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Card title="Memory images (evidence)">
            {data.images.length === 0 ? <EmptyState title="No evidence uploaded">Upload a .raw, .mem, .dmp or .vmem memory image to begin.</EmptyState> : (
              <div className="space-y-4">
                {data.images.map((img) => {
                  const jobs = data.jobs.filter((j) => j.image_id === img.id);
                  const active = jobs.some((j) => j.status === "running" || j.status === "queued");
                  return (
                    <div key={img.id} className="rounded-lg border border-line p-4">
                      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                        <div className="font-medium text-ink">{img.original_filename}</div>
                        <div className="flex gap-2">
                          <Button onClick={() => verify(img)}><ShieldCheck className="h-4 w-4" />Verify hash</Button>
                          <Button variant="primary" disabled={active} onClick={() => setStartFor(img)}><Play className="h-4 w-4" />{jobs.length ? "Re-analyse" : "Start analysis"}</Button>
                        </div>
                      </div>
                      <KeyValue rows={[
                        ["SHA-256", <span key="h"><Mono>{img.sha256}</Mono> <CopyButton text={img.sha256} /></span>],
                        ["Size", fmtBytes(img.size_bytes)],
                        ["Format", img.format_hint],
                        ["Uploaded", fmtTime(img.uploaded_at)],
                        ["OS", img.os_info?.os_name ? `${img.os_info.os_name} ${img.os_info.architecture ?? ""} (build ${img.os_info.build ?? "?"}, confidence ${img.os_info.confidence})` : "Not yet identified"],
                        ["Intake notes", img.validation_notes.join(" ")],
                      ]} />
                      {jobs.length > 0 && (
                        <div className="mt-3 overflow-x-auto">
                          <table className="w-full text-sm">
                            <thead className="text-left text-xs uppercase text-muted"><tr><th className="py-1 pr-3">Analysis</th><th className="pr-3">Status</th><th className="pr-3">Risk</th><th className="pr-3">Hash verified</th><th>Started</th></tr></thead>
                            <tbody>
                              {jobs.map((j) => (
                                <tr key={j.id} className="cursor-pointer border-t border-line hover:bg-surface-2"
                                  onClick={() => nav(j.status.startsWith("completed") ? `/analysis/${j.id}` : `/analysis/${j.id}/progress`)}>
                                  <td className="py-1.5 pr-3 font-medium text-accent">#{j.id}</td>
                                  <td className="pr-3"><StatusPill status={j.status} /></td>
                                  <td className="pr-3"><RiskBadge score={j.overall_risk_score} band={j.overall_risk_band} /></td>
                                  <td className="pr-3 text-xs">{j.hash_verified_before == null ? "-" : `${j.hash_verified_before ? "before ✓" : "before ✗"} ${j.hash_verified_after == null ? "" : j.hash_verified_after ? "/ after ✓" : "/ after ✗"}`}</td>
                                  <td className="text-xs text-muted">{fmtTime(j.started_at)}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </div>
        <Card title="Chain of custody">
          {custody.loading && !custody.data ? <Loading /> : (
            <ol className="relative space-y-3 border-l border-line pl-4">
              {(custody.data ?? []).map((e) => (
                <li key={e.id} className="text-sm">
                  <span className="absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full bg-accent" />
                  <div className="font-medium text-ink">{e.action.replace(/_/g, " ")}</div>
                  <div className="text-xs text-muted">{fmtTime(e.timestamp)} - {e.actor}</div>
                  {e.details && <div className="text-xs text-ink-2">{e.details}</div>}
                  {e.sha256 && <div className="text-[11px]"><Mono>{e.sha256}</Mono></div>}
                </li>
              ))}
            </ol>
          )}
        </Card>
      </div>

      <ConfirmDialog open={confirmClose} title={data.status === "open" ? "Close this case?" : "Re-open this case?"}
        onCancel={() => setConfirmClose(false)} onConfirm={closeCase} confirmLabel={data.status === "open" ? "Close case" : "Re-open"}>
        {data.status === "open" ? "Closed cases cannot receive new evidence. The action is recorded in the chain of custody." : "The case will accept new evidence again."}
      </ConfirmDialog>
      <ConfirmDialog open={!!startFor} title="Start analysis" onCancel={() => setStartFor(null)} onConfirm={start} confirmLabel="Start analysis">
        <p>Run the staged Volatility 3 pipeline against <b>{startFor?.original_filename}</b>. The evidence is re-hashed before and after analysis and is never modified.</p>
        <label className="mt-3 flex items-center gap-2"><input type="checkbox" checked={useYara} onChange={(e) => setUseYara(e.target.checked)} className="accent-[#3987e5]" />Include enabled YARA rules (vadyarascan on triaged processes)</label>
      </ConfirmDialog>
    </Page>
  );
}
