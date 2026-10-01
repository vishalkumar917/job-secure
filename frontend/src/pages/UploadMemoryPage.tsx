import { FileUp, Play } from "lucide-react";
import { useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Page } from "../components/layout/AppLayout";
import { Button, Card, CopyButton, ErrorState, KeyValue, Mono, Notice, PageHeader } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api, uploadImage } from "../services/api";
import { fmtBytes, fmtTime } from "../services/format";
import type { ImageInfo } from "../types";

export default function UploadMemoryPage() {
  const caseId = Number(useParams().caseId);
  const nav = useNavigate();
  const status = useApi(() => api.systemStatus(), []);
  const kase = useApi(() => api.case(caseId), [caseId]);
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ImageInfo | null>(null);
  const [drag, setDrag] = useState(false);

  const allowed = status.data?.limits.allowed_extensions ?? [".raw", ".mem", ".dmp", ".vmem"];
  const maxBytes = status.data?.limits.max_upload_bytes;

  const pick = (f: File | undefined) => {
    setError(null);
    setResult(null);
    if (!f) return;
    const ext = f.name.slice(f.name.lastIndexOf(".")).toLowerCase();
    if (!allowed.includes(ext)) return setError(`Unsupported file type '${ext}'. Accepted: ${allowed.join(", ")}`);
    if (maxBytes && f.size > maxBytes) return setError(`File is larger than the ${fmtBytes(maxBytes)} limit.`);
    setFile(f);
  };

  const upload = async () => {
    if (!file) return;
    setError(null);
    setProgress(0);
    try {
      setResult(await uploadImage(caseId, file, setProgress));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setProgress(null);
    }
  };

  const start = async () => {
    if (!result) return;
    try {
      const job = await api.startAnalysis(result.id, true);
      nav(`/analysis/${job.id}/progress`);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <Page>
      <PageHeader title="Upload memory image" subtitle={kase.data ? `${kase.data.case_number} - ${kase.data.title}` : undefined} />
      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Evidence file" className="lg:col-span-2">
          <div
            onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files[0]); }}
            className={`flex flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-12 text-center ${drag ? "border-accent bg-accent/10" : "border-line-strong"}`}>
            <FileUp className="mb-3 h-8 w-8 text-muted" />
            <div className="text-ink-2">Drag a memory image here, or</div>
            <Button className="mt-2" onClick={() => inputRef.current?.click()}>Choose file</Button>
            <input ref={inputRef} type="file" accept={allowed.join(",")} className="hidden" onChange={(e) => pick(e.target.files?.[0])} />
            <div className="mt-3 text-xs text-muted">Accepted: {allowed.join(", ")}{maxBytes ? ` - max ${fmtBytes(maxBytes)}` : ""}</div>
          </div>
          {file && !result && (
            <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line p-3">
              <div className="min-w-0"><div className="truncate font-medium text-ink">{file.name}</div><div className="text-xs text-muted">{fmtBytes(file.size)}</div></div>
              <Button variant="primary" onClick={upload} disabled={progress !== null}>{progress !== null ? `Uploading ${progress}%` : "Upload and hash"}</Button>
            </div>
          )}
          {progress !== null && (
            <div className="mt-3 h-2 overflow-hidden rounded-full bg-surface-3"><div className="h-full bg-accent transition-all" style={{ width: `${progress}%` }} /></div>
          )}
          {progress === 100 && <p className="mt-2 text-xs text-muted">Upload complete - the server is computing SHA-256 and validating the file...</p>}
          {error && <div className="mt-4"><ErrorState message={error} /></div>}
          {result && (
            <div className="mt-4 space-y-3">
              <Notice tone="ok">Evidence received and stored read-only. Intake hash recorded in the chain of custody.</Notice>
              <KeyValue rows={[
                ["Filename", result.original_filename],
                ["File size", fmtBytes(result.size_bytes)],
                ["SHA-256", <span key="s"><Mono>{result.sha256}</Mono> <CopyButton text={result.sha256} /></span>],
                ["Upload time", fmtTime(result.uploaded_at)],
                ["Detected format", result.format_hint],
                ["Analysis status", "Not started"],
                ["Validation", result.validation_notes.join(" ")],
              ]} />
              <div className="flex gap-2">
                <Button variant="primary" onClick={start}><Play className="h-4 w-4" />Start analysis</Button>
                <Link to={`/investigations/${caseId}`}><Button>Back to case</Button></Link>
              </div>
            </div>
          )}
        </Card>
        <Card title="Evidence handling">
          <ul className="list-disc space-y-2 pl-4 text-sm text-ink-2">
            <li>The file is treated as untrusted input: extension, size and header are validated before acceptance.</li>
            <li>SHA-256 is computed while streaming; the original is stored read-only under a generated name.</li>
            <li>Analysis reads the image without modifying it and re-verifies the hash before and after.</li>
            <li>A raw image has no header - the final validation is whether Volatility can locate a Windows kernel.</li>
          </ul>
          {status.data && !status.data.volatility.available && <div className="mt-3"><Notice tone="warn">Volatility 3 is not installed on the server; uploaded images cannot be analysed until it is.</Notice></div>}
        </Card>
      </div>
    </Page>
  );
}
