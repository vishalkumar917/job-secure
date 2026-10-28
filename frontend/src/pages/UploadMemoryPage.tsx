import { CheckCircle2, Play, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Dropzone, validateImageFile } from "../components/forensic/Dropzone";
import { Page } from "../components/layout/AppLayout";
import { useCrumbs } from "../components/layout/crumbs";
import { Button, Card, CopyButton, ErrorState, KeyValue, Mono, Notice, PageHeader, Switch } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useToast } from "../hooks/useToast";
import { api, uploadImage } from "../services/api";
import { fmtBytes, fmtTime } from "../services/format";
import type { ImageInfo } from "../types";

export default function UploadMemoryPage() {
  const caseId = Number(useParams().caseId);
  const nav = useNavigate();
  const toast = useToast();
  const status = useApi(() => api.systemStatus(), []);
  const kase = useApi(() => api.case(caseId), [caseId]);
  useCrumbs([{ label: "Investigations", to: "/investigations" }, { label: kase.data?.case_number ?? "Investigation", to: `/investigations/${caseId}` }, { label: "Upload memory image" }]);
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ImageInfo | null>(null);
  const [yara, setYara] = useState(true);

  const allowed = status.data?.limits.allowed_extensions ?? [".raw", ".mem", ".dmp", ".vmem"];
  const maxBytes = status.data?.limits.max_upload_bytes;
  const volOk = status.data?.volatility.available ?? true;

  const pick = (f: File) => {
    setResult(null);
    const err = validateImageFile(f, allowed, maxBytes);
    setError(err);
    setFile(err ? null : f);
  };

  const upload = async () => {
    if (!file) return;
    setError(null);
    setProgress(0);
    try {
      const r = await uploadImage(caseId, file, setProgress);
      setResult(r);
      toast({ tone: "success", title: "Memory image uploaded", description: "Intake hash recorded in the chain of custody." });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setProgress(null);
    }
  };

  const start = async () => {
    if (!result) return;
    try {
      const job = await api.startAnalysis(result.id, yara);
      nav(`/analysis/${job.id}/progress`);
    } catch (e) {
      toast({ tone: "error", title: "Could not start analysis", description: (e as Error).message });
    }
  };

  return (
    <Page className="max-w-[1200px]">
      <PageHeader eyebrow={kase.data?.case_number} title="Upload memory image" subtitle={kase.data?.title} />
      <div className="grid gap-6 lg:grid-cols-12">
        <Card className="lg:col-span-8" title="Evidence file" subtitle="Accepted formats are validated here and again on the server.">
          {!result ? (
            <>
              <Dropzone file={file} onFile={pick} onClear={() => setFile(null)} allowed={allowed} maxBytes={maxBytes} disabled={progress !== null} />
              {progress !== null && (
                <div className="mt-6">
                  <div className="mb-2 flex justify-between text-[13px]"><span className="text-ink-2">{progress < 100 ? "Uploading..." : "Computing SHA-256 and validating..."}</span><span className="tabular text-muted">{progress}%</span></div>
                  <div className="h-2 overflow-hidden rounded-full bg-surface-3"><div className="h-full rounded-full bg-accent transition-[width]" style={{ width: `${progress}%` }} /></div>
                </div>
              )}
              {error && <div className="mt-5"><ErrorState compact message={error} /></div>}
              <div className="mt-6 flex justify-end gap-2.5">
                <Button to={`/investigations/${caseId}`} variant="ghost">Cancel</Button>
                <Button variant="primary" onClick={upload} disabled={!file || progress !== null}>{progress !== null ? `Uploading ${progress}%` : "Upload and hash"}</Button>
              </div>
            </>
          ) : (
            <div className="animate-page-in">
              <div className="flex items-center gap-3 text-ink"><CheckCircle2 className="h-6 w-6 text-good-text" /><span className="text-lg font-semibold">Evidence received and stored read-only</span></div>
              <div className="mt-6 rounded-xl border border-line bg-surface-2/50 px-4 py-3">
                <div className="text-xs font-medium uppercase tracking-[0.06em] text-muted">SHA-256 (intake)</div>
                <div className="mt-1 flex flex-wrap items-center gap-2"><Mono className="text-ink">{result.sha256}</Mono><CopyButton text={result.sha256} compact /></div>
              </div>
              <div className="mt-6"><KeyValue cols={2} rows={[
                ["Filename", result.original_filename], ["File size", fmtBytes(result.size_bytes)],
                ["Uploaded (UTC)", fmtTime(result.uploaded_at)], ["Detected format", result.format_hint],
                ["Validation", result.validation_notes.join(" ")], ["Analysis", "Not started"],
              ]} /></div>
              <div className="mt-7"><Switch checked={yara} onChange={setYara} label="Include YARA scanning" description="vadyarascan with enabled rule files on triaged processes" /></div>
              <div className="mt-7 flex flex-wrap gap-2.5">
                <Button variant="primary" onClick={start} disabled={!volOk} icon={<Play />}>Start analysis</Button>
                <Button to={`/investigations/${caseId}`}>Back to case</Button>
              </div>
            </div>
          )}
        </Card>
        <Card className="lg:col-span-4 lg:self-start" title="Evidence handling" icon={<ShieldCheck />}>
          <ul className="space-y-4 text-sm leading-relaxed text-ink-2">
            <li>The file is treated as untrusted input: extension, size and header are validated before acceptance.</li>
            <li>SHA-256 is computed while streaming; the original is stored read-only under a generated name.</li>
            <li>Analysis never modifies the image and re-verifies its hash before and after.</li>
            <li>A raw image has no header - the final validation is whether Volatility can locate a Windows kernel.</li>
          </ul>
          {!volOk && <Notice tone="warn" className="mt-5">Volatility 3 is not installed on the server; uploaded images cannot be analysed until it is.</Notice>}
        </Card>
      </div>
    </Page>
  );
}
