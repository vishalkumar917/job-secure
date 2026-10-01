import { AlertTriangle, CheckCircle2, Info, Loader2, ShieldAlert, X } from "lucide-react";
import { Fragment, useEffect, useState, type ReactNode } from "react";
import type { RiskBand, Severity } from "../../types";

export function cx(...c: (string | false | null | undefined)[]): string {
  return c.filter(Boolean).join(" ");
}

/* ------------------------------------------------------------------ layout primitives */
export function Card({ title, actions, children, className, pad = true }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; pad?: boolean;
}) {
  return (
    <section className={cx("rounded-xl border border-line bg-surface", className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
          <h2 className="text-sm font-semibold text-ink">{title}</h2>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={pad ? "p-4" : ""}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold text-ink">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

export function StatCard({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: "danger" | "warn" | "ok" }) {
  const toneCls = tone === "danger" ? "text-sev-high" : tone === "warn" ? "text-sev-medium" : "text-ink";
  return (
    <div className="rounded-xl border border-line bg-surface px-4 py-3">
      <div className="text-xs font-medium uppercase tracking-wide text-muted">{label}</div>
      <div className={cx("mt-1 text-2xl font-semibold", toneCls)}>{value}</div>
      {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function Button({ children, onClick, variant = "secondary", disabled, type = "button", title, className }: {
  children: ReactNode; onClick?: () => void; variant?: "primary" | "secondary" | "danger" | "ghost";
  disabled?: boolean; type?: "button" | "submit"; title?: string; className?: string;
}) {
  const styles = {
    primary: "bg-accent-strong text-white hover:bg-accent border-transparent",
    secondary: "bg-surface-2 text-ink-2 hover:bg-surface-3 border-line",
    danger: "bg-sev-critical/90 text-white hover:bg-sev-critical border-transparent",
    ghost: "bg-transparent text-ink-2 hover:bg-surface-2 border-transparent",
  }[variant];
  return (
    <button type={type} title={title} onClick={onClick} disabled={disabled}
      className={cx("inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors",
        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:opacity-50",
        styles, className)}>
      {children}
    </button>
  );
}

export const inputCls =
  "w-full rounded-lg border border-line bg-surface-2 px-3 py-2 text-sm text-ink placeholder:text-muted focus:border-accent focus:outline-none";

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-ink-2">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  );
}

/* ------------------------------------------------------------------ severity / risk */
const SEV: Record<Severity, string> = {
  critical: "bg-sev-critical/15 text-[#f08a8a] ring-sev-critical/50",
  high: "bg-sev-high/15 text-sev-high ring-sev-high/50",
  medium: "bg-sev-medium/15 text-sev-medium ring-sev-medium/40",
  low: "bg-sev-low/15 text-[#7fb2f0] ring-sev-low/40",
  info: "bg-surface-3 text-ink-2 ring-line-strong",
};

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const s = (severity in SEV ? severity : "info") as Severity;
  return (
    <span className={cx("inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold capitalize ring-1 ring-inset", SEV[s])}>
      <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-current" />
      {s}
    </span>
  );
}

export const BAND_SEVERITY: Record<RiskBand, Severity> = { critical: "critical", high: "high", moderate: "medium", low: "low" };
export const BAND_COLOR: Record<RiskBand, string> = { critical: "#d03b3b", high: "#ec835a", moderate: "#fab219", low: "#3987e5" };

export function RiskBadge({ score, band }: { score: number | null | undefined; band: RiskBand | null | undefined }) {
  if (score == null || !band) return <span className="text-muted">-</span>;
  return (
    <span className={cx("inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset tabular", SEV[BAND_SEVERITY[band]])}>
      {score}
      <span className="font-medium capitalize opacity-90">{band}</span>
    </span>
  );
}

export function RiskMeter({ score, band }: { score: number; band: RiskBand }) {
  return (
    <div>
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <span className="text-3xl font-semibold text-ink tabular">{score}</span>
        <span className="text-sm text-muted">/ 100</span>
        <span className="text-sm font-semibold capitalize" style={{ color: BAND_COLOR[band] }}>{band}</span>
      </div>
      <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-surface-3" role="meter" aria-valuenow={score} aria-valuemin={0} aria-valuemax={100}>
        <div className="h-full rounded-full" style={{ width: `${score}%`, background: BAND_COLOR[band] }} />
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ states */
export function Loading({ label = "Loading..." }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 p-6 text-sm text-muted" role="status">
      <Loader2 className="h-4 w-4 animate-spin" /> {label}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-wrap items-start gap-3 rounded-xl border border-sev-critical/40 bg-sev-critical/10 p-4 text-sm" role="alert">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-sev-critical" />
      <div className="min-w-0 flex-1 text-ink-2">{message}</div>
      {onRetry && <Button onClick={onRetry}>Retry</Button>}
    </div>
  );
}

export function EmptyState({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <div className="text-muted">{icon ?? <Info className="h-6 w-6" />}</div>
      <div className="font-medium text-ink-2">{title}</div>
      {children && <div className="max-w-md text-sm text-muted">{children}</div>}
    </div>
  );
}

export function Notice({ tone = "info", children }: { tone?: "info" | "warn" | "danger" | "ok"; children: ReactNode }) {
  const map = {
    info: ["border-accent/40 bg-accent/10", <Info key="i" className="h-4 w-4 text-accent" />],
    warn: ["border-sev-medium/40 bg-sev-medium/10", <AlertTriangle key="w" className="h-4 w-4 text-sev-medium" />],
    danger: ["border-sev-critical/40 bg-sev-critical/10", <ShieldAlert key="d" className="h-4 w-4 text-sev-critical" />],
    ok: ["border-good/40 bg-good/10", <CheckCircle2 key="o" className="h-4 w-4 text-good" />],
  } as const;
  return (
    <div className={cx("flex items-start gap-2.5 rounded-lg border px-3 py-2.5 text-sm text-ink-2", map[tone][0])}>
      <span className="mt-0.5 shrink-0">{map[tone][1]}</span>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

export function DemoBanner() {
  return (
    <div className="sticky top-0 z-30 bg-sev-critical px-4 py-1.5 text-center text-xs font-bold tracking-wider text-white">
      DEMO DATA &mdash; NOT REAL FORENSIC EVIDENCE
    </div>
  );
}

/* ------------------------------------------------------------------ dialogs */
export function ConfirmDialog({ open, title, children, confirmLabel = "Confirm", danger, onConfirm, onCancel }: {
  open: boolean; title: string; children: ReactNode; confirmLabel?: string; danger?: boolean;
  onConfirm: () => void; onCancel: () => void;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onCancel();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onCancel]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true" aria-label={title}>
      <div className="w-full max-w-md rounded-xl border border-line bg-surface p-5 shadow-2xl">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="font-semibold text-ink">{title}</h3>
          <button onClick={onCancel} className="text-muted hover:text-ink" aria-label="Close"><X className="h-4 w-4" /></button>
        </div>
        <div className="text-sm text-ink-2">{children}</div>
        <div className="mt-5 flex justify-end gap-2">
          <Button onClick={onCancel}>Cancel</Button>
          <Button variant={danger ? "danger" : "primary"} onClick={onConfirm}>{confirmLabel}</Button>
        </div>
      </div>
    </div>
  );
}

export function Drawer({ open, title, onClose, children }: { open: boolean; title: ReactNode; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onClick={onClose}>
      <aside className="h-full w-full max-w-2xl overflow-y-auto border-l border-line bg-surface p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div className="min-w-0 font-semibold text-ink">{title}</div>
          <button onClick={onClose} className="text-muted hover:text-ink" aria-label="Close"><X className="h-5 w-5" /></button>
        </div>
        {children}
      </aside>
    </div>
  );
}

/* ------------------------------------------------------------------ data display */
export function KeyValue({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(110px,max-content)_1fr] gap-x-4 gap-y-1.5 text-sm">
      {rows.map(([k, v], i) => (
        <Fragment key={i}>
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 break-words text-ink-2">{v ?? <span className="text-muted">unknown</span>}</dd>
        </Fragment>
      ))}
    </dl>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={cx("font-mono text-[0.8rem] break-all text-ink-2", className)}>{children}</code>;
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { key: T; label: ReactNode }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="mb-4 flex flex-wrap gap-1 border-b border-line" role="tablist">
      {tabs.map((t) => (
        <button key={t.key} role="tab" aria-selected={value === t.key} onClick={() => onChange(t.key)}
          className={cx("-mb-px border-b-2 px-3 py-2 text-sm font-medium",
            value === t.key ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink-2")}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button className="text-xs text-accent hover:underline" onClick={() => {
      navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1200); });
    }}>{done ? "copied" : "copy"}</button>
  );
}

export function StatusPill({ status }: { status: string }) {
  const tone = status === "completed" || status === "success" ? "bg-good/15 text-good ring-good/40"
    : status === "failed" || status === "timeout" ? "bg-sev-critical/15 text-[#f08a8a] ring-sev-critical/40"
      : status === "completed_with_errors" ? "bg-sev-medium/15 text-sev-medium ring-sev-medium/40"
        : status === "skipped" ? "bg-surface-3 text-muted ring-line-strong"
          : "bg-accent/15 text-[#7fb2f0] ring-accent/40";
  return <span className={cx("inline-flex rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset", tone)}>{status.replace(/_/g, " ")}</span>;
}

/* ------------------------------------------------------------------ safe Markdown (React elements, no innerHTML) */
function inline(text: string, onCite?: (id: string) => void): ReactNode[] {
  const parts: ReactNode[] = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\[(?:F|PROC|NET|MEM|MOD|IOC|YARA|TL)-[\w.]+\]|\[SUMMARY\])/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let k = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("**")) parts.push(<strong key={k++} className="text-ink">{tok.slice(2, -2)}</strong>);
    else if (tok.startsWith("`")) parts.push(<code key={k++}>{tok.slice(1, -1)}</code>);
    else {
      const id = tok.slice(1, -1);
      parts.push(
        <button key={k++} onClick={() => onCite?.(id)}
          className="mx-0.5 rounded bg-accent/15 px-1 font-mono text-[0.72rem] text-[#7fb2f0] ring-1 ring-accent/30 hover:bg-accent/25">
          {id}
        </button>,
      );
    }
    last = m.index + tok.length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}

export function Markdown({ text, onCite }: { text: string; onCite?: (id: string) => void }) {
  const blocks: ReactNode[] = [];
  let key = 0;
  let list: { ordered: boolean; items: ReactNode[] } | null = null;
  const flush = () => {
    if (list) {
      blocks.push(list.ordered ? <ol key={`b${key++}`}>{list.items}</ol> : <ul key={`b${key++}`}>{list.items}</ul>);
      list = null;
    }
  };
  text.split("\n").forEach((raw, i) => {
    const line = raw.trimEnd();
    const ul = /^\s*-\s+(.*)/.exec(line);
    const ol = /^\s*\d+\.\s+(.*)/.exec(line);
    if (ul || ol) {
      const ordered = !!ol;
      if (!list || list.ordered !== ordered) {
        flush();
        list = { ordered, items: [] };
      }
      list.items.push(<li key={i}>{inline((ul ?? ol)![1], onCite)}</li>);
      return;
    }
    flush();
    if (!line.trim()) return;
    const k = `b${key++}`;
    if (line.startsWith("### ")) blocks.push(<h4 key={k}>{inline(line.slice(4), onCite)}</h4>);
    else if (line.startsWith("> ")) blocks.push(<blockquote key={k}>{inline(line.slice(2), onCite)}</blockquote>);
    else if (line === "---") blocks.push(<hr key={k} />);
    else blocks.push(<p key={k}>{inline(line, onCite)}</p>);
  });
  flush();
  return <div className="md text-sm leading-relaxed text-ink-2">{blocks}</div>;
}
