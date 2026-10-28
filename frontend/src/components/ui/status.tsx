import { AlertOctagon, AlertTriangle, CheckCircle2, CircleDot, Info, Loader2, MinusCircle, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import type { RiskBand, Severity } from "../../types";
import { confidenceLabel } from "../../services/format";
import { cx } from "./primitives";

/* Severity is always rendered as dot/icon + text label, never colour alone. */
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const sevRank = (s: string) => { const i = SEVERITIES.indexOf(s as Severity); return i < 0 ? SEVERITIES.length : i; };

/** CSS colour (token reference) for a severity - for HTML style props. Charts use useChartTheme + SEV_HEX. */
export const SEV_VAR: Record<Severity, string> = {
  critical: "var(--color-sev-critical)", high: "var(--color-sev-high)", medium: "var(--color-sev-medium)",
  low: "var(--color-sev-low)", info: "var(--color-sev-info)",
};
export const SEV_HEX: Record<Severity, string> = { critical: "#d03b3b", high: "#ec835a", medium: "#fab219", low: "#3987e5", info: "#7f8a9c" };

const SEV_CLS: Record<Severity, string> = {
  critical: "bg-sev-critical/12 text-sev-critical-text ring-sev-critical/30",
  high: "bg-sev-high/12 text-sev-high-text ring-sev-high/30",
  medium: "bg-sev-medium/12 text-sev-medium-text ring-sev-medium/30",
  low: "bg-sev-low/12 text-sev-low-text ring-sev-low/30",
  info: "bg-surface-2 text-sev-info-text ring-line-strong",
};

export const BAND_SEVERITY: Record<RiskBand, Severity> = { critical: "critical", high: "high", moderate: "medium", low: "low" };
export const BAND_COLOR: Record<RiskBand, string> = {
  critical: SEV_VAR.critical, high: SEV_VAR.high, moderate: SEV_VAR.medium, low: SEV_VAR.low,
};
export const BAND_HEX: Record<RiskBand, string> = { critical: SEV_HEX.critical, high: SEV_HEX.high, moderate: SEV_HEX.medium, low: SEV_HEX.low };

const asSev = (s: string): Severity => (SEVERITIES.includes(s as Severity) ? (s as Severity) : "info");

export function SeverityDot({ severity, className }: { severity: Severity | string; className?: string }) {
  return <span aria-hidden className={cx("inline-block h-2 w-2 shrink-0 rounded-full", className)} style={{ background: SEV_VAR[asSev(severity)] }} />;
}

export function SeverityBadge({ severity, size = "sm" }: { severity: Severity | string; size?: "sm" | "md" }) {
  const s = asSev(severity);
  return (
    <span className={cx("inline-flex shrink-0 items-center gap-1.5 rounded-md font-semibold uppercase tracking-[0.04em] ring-1 ring-inset",
      size === "md" ? "px-2.5 py-1 text-[11.5px]" : "px-2 py-0.5 text-[10.5px]", SEV_CLS[s])}>
      <SeverityDot severity={s} className={size === "md" ? "h-2 w-2" : "h-1.5 w-1.5"} />
      {s}
    </span>
  );
}

export function RiskBadge({ score, band, showBand = true }: { score: number | null | undefined; band: RiskBand | null | undefined; showBand?: boolean }) {
  if (score == null || !band) return <span className="text-faint">-</span>;
  return (
    <span className={cx("inline-flex shrink-0 items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset", SEV_CLS[BAND_SEVERITY[band]])}>
      <span className="tabular">{score}</span>
      {showBand && <span className="font-medium capitalize opacity-90">{band}</span>}
    </span>
  );
}

/** Compact horizontal risk score bar used in tables. */
export function RiskBar({ score, band }: { score: number; band: RiskBand }) {
  return (
    <div className="flex items-center gap-2.5">
      <span className="w-7 text-right text-sm font-semibold tabular text-ink">{score}</span>
      <span className="relative h-1.5 w-16 overflow-hidden rounded-full bg-surface-3" aria-hidden>
        <span className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${Math.max(score, 3)}%`, background: score > 0 ? BAND_COLOR[band] : "var(--color-line-strong)" }} />
      </span>
      <span className="text-xs capitalize text-muted">{score > 0 ? band : "none"}</span>
    </div>
  );
}

const STATUS: Record<string, { cls: string; icon: ReactNode }> = {
  completed: { cls: "bg-good/10 text-good-text ring-good/25", icon: <CheckCircle2 /> },
  success: { cls: "bg-good/10 text-good-text ring-good/25", icon: <CheckCircle2 /> },
  open: { cls: "bg-accent-soft text-accent-text ring-accent/25", icon: <CircleDot /> },
  failed: { cls: "bg-sev-critical/10 text-sev-critical-text ring-sev-critical/25", icon: <XCircle /> },
  timeout: { cls: "bg-sev-critical/10 text-sev-critical-text ring-sev-critical/25", icon: <XCircle /> },
  completed_with_errors: { cls: "bg-sev-medium/10 text-sev-medium-text ring-sev-medium/25", icon: <AlertTriangle /> },
  skipped: { cls: "bg-surface-2 text-muted ring-line-strong", icon: <MinusCircle /> },
  closed: { cls: "bg-surface-2 text-muted ring-line-strong", icon: <MinusCircle /> },
  running: { cls: "bg-accent-soft text-accent-text ring-accent/25", icon: <Loader2 className="animate-spin" /> },
  queued: { cls: "bg-surface-2 text-ink-2 ring-line-strong", icon: <CircleDot /> },
};

export function StatusPill({ status, label }: { status: string; label?: string }) {
  const s = STATUS[status] ?? { cls: "bg-surface-2 text-ink-2 ring-line-strong", icon: <CircleDot /> };
  return (
    <span className={cx("inline-flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ring-1 ring-inset [&_svg]:h-3.5 [&_svg]:w-3.5", s.cls)}>
      {s.icon}{label ?? status.replace(/_/g, " ")}
    </span>
  );
}

/** Confidence as a 5-segment meter plus label and numeric value. */
export function ConfidenceMeter({ value, showValue = true }: { value: number; showValue?: boolean }) {
  const label = confidenceLabel(value);
  const filled = Math.max(1, Math.round(value * 5));
  const color = label === "High" ? "var(--color-accent)" : label === "Medium" ? "var(--color-cyan)" : "var(--color-faint)";
  return (
    <span className="inline-flex items-center gap-2" title={`Confidence ${value.toFixed(2)} (${label})`}>
      <span className="flex gap-[3px]" aria-hidden>
        {[0, 1, 2, 3, 4].map((i) => (
          <span key={i} className="h-3 w-[5px] rounded-[2px]" style={{ background: i < filled ? color : "var(--color-surface-3)" }} />
        ))}
      </span>
      <span className="text-[13px] font-medium text-ink-2">{label}</span>
      {showValue && <span className="text-xs tabular text-muted">{Math.round(value * 100)}%</span>}
    </span>
  );
}

/** Evidence source label (e.g. windows.malfind) - shows where a fact came from. */
export function SourceTag({ source, className }: { source: string; className?: string }) {
  return (
    <span className={cx("inline-flex shrink-0 items-center rounded-md border border-line bg-surface-2 px-1.5 py-px font-mono text-[11px] text-ink-2", className)}>
      {source.replace(/^windows\./, "")}
    </span>
  );
}

type Tone = "neutral" | "accent" | "danger" | "warning" | "success";
const TONE: Record<Tone, string> = {
  neutral: "bg-surface-2 text-ink-2 ring-line",
  accent: "bg-accent-soft text-accent-text ring-accent/20",
  danger: "bg-sev-critical/10 text-sev-critical-text ring-sev-critical/25",
  warning: "bg-sev-medium/10 text-sev-medium-text ring-sev-medium/25",
  success: "bg-good/10 text-good-text ring-good/25",
};
export function Badge({ children, tone = "neutral", icon, className }: { children: ReactNode; tone?: Tone; icon?: ReactNode; className?: string }) {
  return (
    <span className={cx("inline-flex shrink-0 items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-semibold ring-1 ring-inset [&_svg]:h-3 [&_svg]:w-3", TONE[tone], className)}>
      {icon}{children}
    </span>
  );
}

export function DemoTag() {
  return <Badge tone="danger" icon={<AlertOctagon />}>DEMO</Badge>;
}

export function InfoTag({ children }: { children: ReactNode }) {
  return <Badge icon={<Info />}>{children}</Badge>;
}
