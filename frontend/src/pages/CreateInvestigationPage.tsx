import { ArrowLeft, ArrowRight, Check, CheckCircle2, Circle, FileSearch, FolderPlus, HardDrive, Loader2, Pencil, Play, Settings2, ShieldCheck, XCircle } from "lucide-react";
import { useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { Dropzone, validateImageFile } from "../components/forensic/Dropzone";
import { Page } from "../components/layout/AppLayout";
import { useCrumbs } from "../components/layout/crumbs";
import { Button, Card, cx, ErrorState, Field, inputCls, Notice, PageHeader, Switch, textareaCls } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useToast } from "../hooks/useToast";
import { api, uploadImage } from "../services/api";
import { fmtBytes, STAGES } from "../services/format";
import type { Case, ImageInfo } from "../types";

const STEPS = [
  { title: "Case information", icon: <FolderPlus /> },
  { title: "Memory image", icon: <HardDrive /> },
  { title: "Configure analysis", icon: <Settings2 /> },
  { title: "Review", icon: <FileSearch /> },
  { title: "Start investigation", icon: <Play /> },
];
const CASE_NO = /^[A-Za-z0-9_-]{3,32}$/;

type RunState = "pending" | "running" | "done" | "error" | "skipped";

function Stepper({ step }: { step: number }) {
  return (
    <>
      <div className="mb-8 md:hidden">
        <div className="text-xs font-semibold uppercase tracking-[0.08em] text-accent-text">Step {step + 1} of {STEPS.length}</div>
        <div className="mt-1 text-lg font-semibold text-ink">{STEPS[step].title}</div>
        <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-surface-3">
          <div className="h-full rounded-full bg-accent transition-[width] duration-500" style={{ width: `${((step + 1) / STEPS.length) * 100}%` }} />
        </div>
      </div>
      <ol className="mb-10 hidden items-center md:flex" aria-label="Progress">
        {STEPS.map((s, i) => {
          const done = i < step, cur = i === step;
          return (
            <li key={s.title} className={cx("flex items-center", i < STEPS.length - 1 && "flex-1")} aria-current={cur ? "step" : undefined}>
              <div className="flex items-center gap-3">
                <span className={cx("flex h-9 w-9 shrink-0 items-center justify-center rounded-full border-2 text-sm font-semibold transition-colors duration-300",
                  done ? "border-accent bg-accent text-white" : cur ? "border-accent bg-accent-soft text-accent-text" : "border-line-strong text-faint")}>
                  {done ? <Check className="h-4 w-4" /> : i + 1}
                </span>
                <span className={cx("whitespace-nowrap text-sm font-medium", cur ? "text-ink" : done ? "text-ink-2" : "text-faint")}>{s.title}</span>
              </div>
              {i < STEPS.length - 1 && <span className={cx("mx-4 h-0.5 flex-1 rounded-full transition-colors duration-500", done ? "bg-accent" : "bg-line")} />}
            </li>
          );
        })}
      </ol>
    </>
  );
}

function ReviewRow({ label, value, onEdit }: { label: string; value: ReactNode; onEdit: () => void }) {
  return (
    <div className="flex flex-wrap items-start gap-x-6 gap-y-1 py-4 first:pt-0 last:pb-0">
      <dt className="w-44 shrink-0 text-[13px] font-medium text-muted">{label}</dt>
      <dd className="min-w-0 flex-1 break-words text-sm text-ink">{value}</dd>
      <button type="button" onClick={onEdit} className="inline-flex items-center gap-1 text-[13px] font-medium text-accent-text hover:underline"><Pencil className="h-3.5 w-3.5" />Edit</button>
    </div>
  );
}

export default function CreateInvestigationPage() {
  useCrumbs([{ label: "Investigations", to: "/investigations" }, { label: "New investigation" }]);
  const nav = useNavigate();
  const toast = useToast();
  const status = useApi(() => api.systemStatus(), []);
  const allowed = status.data?.limits.allowed_extensions ?? [".raw", ".mem", ".dmp", ".vmem"];
  const maxBytes = status.data?.limits.max_upload_bytes;
  const volOk = status.data?.volatility.available ?? true;

  const [step, setStep] = useState(0);
  const [title, setTitle] = useState("");
  const [caseNumber, setCaseNumber] = useState("");
  const [description, setDescription] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [fileErr, setFileErr] = useState<string | null>(null);
  const [yara, setYara] = useState(true);
  const [autoStart, setAutoStart] = useState(true);
  const [touched, setTouched] = useState(false);

  const [created, setCreated] = useState<Case | null>(null);
  const [uploaded, setUploaded] = useState<ImageInfo | null>(null);
  const [run, setRun] = useState<Record<"case" | "upload" | "analysis", RunState>>({ case: "pending", upload: "pending", analysis: "pending" });
  const [pct, setPct] = useState(0);
  const [runErr, setRunErr] = useState<string | null>(null);

  const titleErr = title.trim().length < 3 ? "Enter a title of at least 3 characters." : null;
  const numErr = caseNumber.trim() && !CASE_NO.test(caseNumber.trim()) ? "3-32 characters: letters, digits, '-' and '_'." : null;

  const next = () => {
    if (step === 0) {
      setTouched(true);
      if (titleErr || numErr) return;
    }
    setStep((s) => Math.min(s + 1, STEPS.length - 1));
  };

  const pick = (f: File) => {
    const err = validateImageFile(f, allowed, maxBytes);
    setFileErr(err);
    setFile(err ? null : f);
  };

  const execute = async () => {
    setStep(4);
    setRunErr(null);
    let kase = created;
    try {
      if (!kase) {
        setRun((r) => ({ ...r, case: "running" }));
        kase = await api.createCase({ title: title.trim(), description: description.trim(), case_number: caseNumber.trim() || undefined });
        setCreated(kase);
      }
      setRun((r) => ({ ...r, case: "done" }));
      if (!file) {
        setRun((r) => ({ ...r, upload: "skipped", analysis: "skipped" }));
        toast({ tone: "success", title: `Investigation ${kase.case_number} created` });
        window.setTimeout(() => nav(`/investigations/${kase!.id}`), 900);
        return;
      }
      let img = uploaded;
      if (!img) {
        setRun((r) => ({ ...r, upload: "running" }));
        setPct(0);
        img = await uploadImage(kase.id, file, setPct);
        setUploaded(img);
        toast({ tone: "success", title: "Memory image uploaded", description: `SHA-256 ${img.sha256.slice(0, 16)}... recorded in the chain of custody.` });
      }
      setRun((r) => ({ ...r, upload: "done" }));
      if (!autoStart || !volOk) {
        setRun((r) => ({ ...r, analysis: "skipped" }));
        window.setTimeout(() => nav(`/investigations/${kase!.id}`), 900);
        return;
      }
      setRun((r) => ({ ...r, analysis: "running" }));
      const job = await api.startAnalysis(img.id, yara);
      setRun((r) => ({ ...r, analysis: "done" }));
      window.setTimeout(() => nav(`/analysis/${job.id}/progress`), 700);
    } catch (e) {
      setRunErr((e as Error).message);
      setRun((r) => {
        const out = { ...r };
        (Object.keys(out) as (keyof typeof out)[]).forEach((k) => { if (out[k] === "running") out[k] = "error"; });
        return out;
      });
    }
  };

  const RunRow = ({ state, title: t, detail }: { state: RunState; title: string; detail: ReactNode }) => (
    <li className="flex items-start gap-4 py-5 first:pt-0 last:pb-0">
      <span className="mt-0.5">
        {state === "done" ? <CheckCircle2 className="h-5 w-5 text-good-text" /> : state === "running" ? <Loader2 className="h-5 w-5 animate-spin text-accent-text" />
          : state === "error" ? <XCircle className="h-5 w-5 text-sev-critical-text" /> : <Circle className={cx("h-5 w-5", state === "skipped" ? "text-faint" : "text-line-strong")} />}
      </span>
      <div className="min-w-0 flex-1">
        <div className={cx("text-[15px] font-medium", state === "pending" || state === "skipped" ? "text-muted" : "text-ink")}>{t}{state === "skipped" && " - skipped"}</div>
        <div className="mt-0.5 text-[13px] text-muted">{detail}</div>
      </div>
    </li>
  );

  return (
    <Page className="max-w-[1040px]">
      <PageHeader eyebrow="New investigation" title="Create a forensic investigation"
        subtitle="Open a case, add a Windows memory image and start the evidence pipeline. Every action is written to the chain of custody." />
      <Stepper step={step} />

      {step === 0 && (
        <Card title="Case information" subtitle="Describe the scope and origin of the evidence.">
          <div className="grid gap-6">
            <Field label="Title" error={touched ? titleErr ?? undefined : undefined}>
              <input className={inputCls} value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} autoFocus
                placeholder="e.g. Workstation WS-0142 suspected compromise" />
            </Field>
            <Field label="Case number" optional error={numErr ?? undefined} hint="Leave blank to generate CASE-YYYY-NNNN automatically.">
              <input className={`${inputCls} font-mono sm:max-w-xs`} value={caseNumber} onChange={(e) => setCaseNumber(e.target.value)} placeholder="CASE-2026-0042" />
            </Field>
            <Field label="Description" optional hint="Scope, acquisition tool and time, source host, authorisation reference.">
              <textarea className={textareaCls} rows={5} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={5000}
                placeholder="Memory acquired with WinPmem on 2026-03-14 08:42 UTC from WS-0142 under IR ticket #1187..." />
            </Field>
          </div>
        </Card>
      )}

      {step === 1 && (
        <Card title="Memory image" subtitle="Raw (.raw/.mem), VMware (.vmem) or crash dump (.dmp). The file is treated as untrusted input.">
          <Dropzone file={file} onFile={pick} onClear={() => setFile(null)} allowed={allowed} maxBytes={maxBytes} />
          {fileErr && <div className="mt-4"><ErrorState compact message={fileErr} /></div>}
          <ul className="mt-6 grid gap-3 text-[13px] text-muted sm:grid-cols-3">
            <li className="flex gap-2.5"><ShieldCheck className="h-4 w-4 shrink-0 text-good-text" />SHA-256 computed while streaming</li>
            <li className="flex gap-2.5"><ShieldCheck className="h-4 w-4 shrink-0 text-good-text" />Stored read-only under a generated name</li>
            <li className="flex gap-2.5"><ShieldCheck className="h-4 w-4 shrink-0 text-good-text" />Header validated before acceptance</li>
          </ul>
          {!file && <p className="mt-6 text-[13px] text-muted">No image yet? You can continue and add evidence to the case later.</p>}
        </Card>
      )}

      {step === 2 && (
        <div className="grid gap-6 lg:grid-cols-5">
          <Card className="lg:col-span-3" title="Analysis options">
            <div className="space-y-6">
              <Switch checked={autoStart} onChange={setAutoStart} disabled={!file}
                label="Start analysis after upload" description={file ? "Run the Volatility 3 pipeline as soon as the image is hashed and stored." : "Requires a memory image."} />
              <Switch checked={yara} onChange={setYara} disabled={!file || !autoStart}
                label="Include YARA scanning" description="Scan triaged processes with enabled YARA rule files (windows.vadyarascan)." />
              {!volOk && <Notice tone="warn">Volatility 3 is not installed on the server, so analysis cannot start. The image will still be stored and hashed.</Notice>}
            </div>
          </Card>
          <Card className="lg:col-span-2" title="Pipeline stages" subtitle="Run in order; each plugin run is logged with its output hash.">
            <ol className="space-y-3">
              {STAGES.filter((s) => s.key !== "completed").map((s, i) => (
                <li key={s.key} className="flex gap-3 text-[13px]">
                  <span className="w-5 shrink-0 text-right font-mono text-faint">{i + 1}</span>
                  <span className="text-ink-2">{s.label}</span>
                </li>
              ))}
            </ol>
          </Card>
        </div>
      )}

      {step === 3 && (
        <Card title="Review" subtitle="Nothing has been created yet. Confirm the details below.">
          <dl className="divide-y divide-line">
            <ReviewRow label="Title" value={title} onEdit={() => setStep(0)} />
            <ReviewRow label="Case number" value={caseNumber ? <span className="font-mono">{caseNumber}</span> : <span className="text-muted">Generated automatically</span>} onEdit={() => setStep(0)} />
            <ReviewRow label="Description" value={description || <span className="text-muted">None</span>} onEdit={() => setStep(0)} />
            <ReviewRow label="Memory image" value={file ? `${file.name} (${fmtBytes(file.size)})` : <span className="text-muted">None - add later</span>} onEdit={() => setStep(1)} />
            <ReviewRow label="Analysis" value={!file ? "Not started" : autoStart && volOk ? `Start automatically${yara ? " · with YARA" : " · without YARA"}` : "Start manually later"} onEdit={() => setStep(2)} />
          </dl>
        </Card>
      )}

      {step === 4 && (
        <Card title="Starting investigation" subtitle="Keep this page open while the image uploads.">
          <ol className="divide-y divide-line">
            <RunRow state={run.case} title="Create case" detail={created ? `${created.case_number} opened - custody event recorded` : "Open the case record"} />
            <RunRow state={run.upload} title="Upload and hash memory image"
              detail={run.upload === "running" ? (
                <span className="mt-2 block max-w-md">
                  <span className="block h-1.5 overflow-hidden rounded-full bg-surface-3"><span className="block h-full rounded-full bg-accent transition-[width]" style={{ width: `${pct}%` }} /></span>
                  <span className="mt-1.5 block tabular">{pct < 100 ? `Uploading ${pct}%` : "Upload complete - computing SHA-256 and validating..."}</span>
                </span>
              ) : file ? `${file.name} · ${fmtBytes(file.size)}` : "No image selected"} />
            <RunRow state={run.analysis} title="Start analysis" detail={yara ? "Volatility 3 pipeline with YARA" : "Volatility 3 pipeline"} />
          </ol>
          {runErr && (
            <div className="mt-6">
              <ErrorState title="The investigation could not be started" message={runErr} onRetry={execute}
                actions={created && <Button to={`/investigations/${created.id}`}>Go to {created.case_number}</Button>} />
            </div>
          )}
        </Card>
      )}

      {step < 4 && (
        <div className="mt-8 flex flex-wrap items-center justify-between gap-3">
          <Button variant="ghost" onClick={() => (step === 0 ? nav(-1) : setStep(step - 1))} icon={<ArrowLeft />}>{step === 0 ? "Cancel" : "Back"}</Button>
          {step < 3 ? <Button variant="primary" onClick={next}>Continue <ArrowRight /></Button>
            : <Button variant="primary" size="lg" onClick={execute} icon={<Play />}>Start investigation</Button>}
        </div>
      )}
    </Page>
  );
}
