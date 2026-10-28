import { FileUp, HardDrive, X } from "lucide-react";
import { useRef, useState } from "react";
import { fmtBytes } from "../../services/format";
import { Button, cx } from "../ui";

/** Validates extension and size client-side; the server repeats every check (the file is untrusted input). */
export function validateImageFile(f: File, allowed: string[], maxBytes?: number): string | null {
  const ext = f.name.includes(".") ? f.name.slice(f.name.lastIndexOf(".")).toLowerCase() : "";
  if (!allowed.includes(ext)) return `Unsupported file type '${ext || "none"}'. Accepted: ${allowed.join(", ")}`;
  if (maxBytes && f.size > maxBytes) return `File is larger than the ${fmtBytes(maxBytes)} limit.`;
  return null;
}

export function Dropzone({ file, onFile, onClear, allowed, maxBytes, disabled }: {
  file: File | null; onFile: (f: File) => void; onClear?: () => void; allowed: string[]; maxBytes?: number; disabled?: boolean;
}) {
  const ref = useRef<HTMLInputElement>(null);
  const [drag, setDrag] = useState(false);

  if (file) {
    return (
      <div className="flex items-center gap-4 rounded-2xl border border-line bg-surface-2/60 p-5">
        <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-accent-soft text-accent-text"><HardDrive className="h-5 w-5" /></span>
        <div className="min-w-0 flex-1">
          <div className="truncate font-medium text-ink">{file.name}</div>
          <div className="mt-0.5 text-[13px] text-muted">{fmtBytes(file.size)} · {file.name.slice(file.name.lastIndexOf(".")).toLowerCase()} memory image</div>
        </div>
        {onClear && !disabled && (
          <button type="button" onClick={onClear} aria-label="Remove file" className="rounded-lg p-2 text-muted hover:bg-surface-3 hover:text-ink"><X className="h-4 w-4" /></button>
        )}
      </div>
    );
  }

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
      onDrop={(e) => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files[0]; if (f) onFile(f); }}
      className={cx("flex flex-col items-center justify-center rounded-2xl border-2 border-dashed px-6 py-14 text-center transition-colors duration-200",
        drag ? "border-accent bg-accent-soft" : "border-line-strong bg-surface-2/30 hover:border-faint")}>
      <span className={cx("mb-5 flex h-14 w-14 items-center justify-center rounded-2xl transition-colors", drag ? "bg-accent text-white" : "bg-surface-2 text-muted")}>
        <FileUp className="h-6 w-6" />
      </span>
      <div className="text-[15px] font-medium text-ink">Drop a memory image here</div>
      <div className="mt-1 text-sm text-muted">or browse your files</div>
      <Button className="mt-5" onClick={() => ref.current?.click()} disabled={disabled}>Choose file</Button>
      <input ref={ref} type="file" accept={allowed.join(",")} className="hidden"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) onFile(f); e.target.value = ""; }} />
      <div className="mt-5 text-xs text-faint">{allowed.join("  ·  ")}{maxBytes ? `  ·  up to ${fmtBytes(maxBytes)}` : ""}</div>
    </div>
  );
}
