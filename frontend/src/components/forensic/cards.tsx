import { ArrowRight, ArrowUpRight } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import type { EvidenceItem, Finding, RiskBand } from "../../types";
import { CATEGORY_LABEL } from "../../services/format";
import { BAND_COLOR, ConfidenceMeter, cx, Mono, SeverityBadge, SEV_VAR, SourceTag } from "../ui";

/* ------------------------------------------------------------------ metric */
export function MetricCard({ label, value, icon, hint, tone, to, className }: {
  label: string; value: ReactNode; icon?: ReactNode; hint?: ReactNode; tone?: "danger" | "warning" | "accent"; to?: string; className?: string;
}) {
  const toneCls = tone === "danger" ? "text-sev-critical-text bg-sev-critical/10" : tone === "warning" ? "text-sev-medium-text bg-sev-medium/10"
    : tone === "accent" ? "text-accent-text bg-accent-soft" : "text-ink-2 bg-surface-2";
  const body = (
    <>
      <div className="flex items-start justify-between gap-3">
        <span className="text-[13px] font-medium text-muted">{label}</span>
        {icon && <span className={cx("flex h-9 w-9 shrink-0 items-center justify-center rounded-xl [&_svg]:h-[18px] [&_svg]:w-[18px]", toneCls)}>{icon}</span>}
      </div>
      <div className="mt-3 text-[32px] font-semibold leading-none tracking-[-0.02em] text-ink">{value}</div>
      {hint && <div className="mt-3 text-[13px] leading-snug text-muted">{hint}</div>}
      {to && <ArrowUpRight className="absolute bottom-5 right-5 h-4 w-4 text-faint opacity-0 transition-opacity group-hover:opacity-100" />}
    </>
  );
  const cls = cx("group relative block min-w-0 rounded-2xl border border-line bg-surface p-6 shadow-card transition-[border-color,box-shadow,transform] duration-200",
    to && "hover:-translate-y-px hover:border-line-strong hover:shadow-raised", className);
  return to ? <Link to={to} className={cls}>{body}</Link> : <div className={cls}>{body}</div>;
}

/* ------------------------------------------------------------------ risk */
const BAND_LABEL: Record<RiskBand, string> = { critical: "Critical", high: "High", moderate: "Moderate", low: "Low" };

/** Semicircular gauge with band thresholds (30 / 60 / 80) marked on the track. */
export function RiskGauge({ score, band, size = 220 }: { score: number; band: RiskBand; size?: number }) {
  const r = 82, cxp = 100, cyp = 100;
  const pt = (f: number, rad = r) => {
    const a = Math.PI * (1 - f);
    return [cxp + rad * Math.cos(a), cyp - rad * Math.sin(a)];
  };
  const arc = `M ${cxp - r} ${cyp} A ${r} ${r} 0 0 1 ${cxp + r} ${cyp}`;
  return (
    <div className="relative mx-auto" style={{ width: size, maxWidth: "100%" }} role="meter" aria-valuenow={score} aria-valuemin={0} aria-valuemax={100}
      aria-label={`Risk score ${score} of 100, ${BAND_LABEL[band]}`}>
      <svg viewBox="0 0 200 112" className="w-full overflow-visible">
        <path d={arc} fill="none" stroke="var(--color-surface-3)" strokeWidth={14} strokeLinecap="round" />
        <path d={arc} fill="none" stroke={BAND_COLOR[band]} strokeWidth={14} strokeLinecap="round" pathLength={100}
          strokeDasharray={`${Math.max(score, 0.5)} 100`} style={{ transition: "stroke-dasharray 0.8s cubic-bezier(0.22,1,0.36,1)" }} />
        {[30, 60, 80].map((t) => {
          const [x1, y1] = pt(t / 100, r - 11);
          const [x2, y2] = pt(t / 100, r - 17);
          return <line key={t} x1={x1} y1={y1} x2={x2} y2={y2} stroke="var(--color-faint)" strokeWidth={1.5} strokeLinecap="round" />;
        })}
      </svg>
      <div className="absolute inset-x-0 bottom-0 flex flex-col items-center">
        <span className="text-[44px] font-semibold leading-none tracking-[-0.03em] text-ink">{score}</span>
        <span className="mt-2 text-xs font-bold uppercase tracking-[0.14em]" style={{ color: BAND_COLOR[band] }}>{BAND_LABEL[band]}</span>
      </div>
    </div>
  );
}

export function RiskCard({ title = "Overall investigation risk", score, band, findings, footer, className, children }: {
  title?: string; score: number; band: RiskBand; findings?: number; footer?: ReactNode; className?: string; children?: ReactNode;
}) {
  return (
    <section className={cx("flex min-w-0 flex-col rounded-2xl border border-line bg-surface p-6 shadow-card md:p-7", className)}>
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-base font-semibold text-ink">{title}</h2>
        <span className="text-xs text-muted">0-100</span>
      </div>
      <div className="mt-6"><RiskGauge score={score} band={band} /></div>
      <div className="mt-7">
        <div className="relative h-2 overflow-hidden rounded-full bg-surface-3">
          <div className="absolute inset-y-0 left-0 rounded-full transition-[width] duration-700" style={{ width: `${score}%`, background: BAND_COLOR[band] }} />
          {[30, 60, 80].map((t) => <span key={t} className="absolute inset-y-0 w-px bg-surface" style={{ left: `${t}%` }} />)}
        </div>
        <div className="mt-2 flex justify-between text-[11px] tabular text-faint"><span>0</span><span>30</span><span>60</span><span>80</span><span>100</span></div>
      </div>
      {findings != null && <p className="mt-5 text-sm text-muted">Based on <span className="font-semibold text-ink">{findings}</span> forensic finding{findings === 1 ? "" : "s"}</p>}
      {children}
      {footer && <div className="mt-auto pt-5 text-xs leading-relaxed text-muted">{footer}</div>}
    </section>
  );
}

/* ------------------------------------------------------------------ findings */
export function FindingCard({ finding: f, jobId, onOpen, compact }: { finding: Finding; jobId: number; onOpen?: (f: Finding) => void; compact?: boolean }) {
  const ev = f.evidence[0];
  return (
    <article className={cx("group relative rounded-xl border border-line bg-surface transition-[border-color,box-shadow] duration-200 hover:border-line-strong hover:shadow-raised",
      compact ? "p-5" : "p-6")}>
      <span aria-hidden className="absolute inset-y-5 left-0 w-[3px] rounded-r-full" style={{ background: SEV_VAR[f.severity] }} />
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <SeverityBadge severity={f.severity} />
        <span className="text-xs text-muted">{CATEGORY_LABEL[f.category] ?? f.category}</span>
        <span className="ml-auto"><ConfidenceMeter value={f.confidence} /></span>
      </div>
      <h3 className="mt-3 text-[15px] font-semibold leading-snug text-ink">{f.title}</h3>
      {f.pid != null && (
        <div className="mt-1.5 flex flex-wrap items-center gap-x-2 text-[13px] text-muted">
          <Link to={`/analysis/${jobId}/processes/${f.pid}`} onClick={(e) => e.stopPropagation()} className="font-medium text-ink-2 hover:text-accent-text hover:underline">
            {f.process_name}
          </Link>
          <span className="font-mono tabular">PID {f.pid}</span>
        </div>
      )}
      {!compact && <p className="mt-3 text-sm leading-relaxed text-ink-2">{f.finding}</p>}
      {ev && (
        <div className="mt-4 rounded-lg border border-line bg-surface-2/60 px-3.5 py-2.5">
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted"><SourceTag source={ev.source} />{ev.description}</div>
          <div className="mt-1.5 line-clamp-2 font-mono text-[12.5px] break-all text-ink-2" title={ev.value}>{ev.value}</div>
        </div>
      )}
      {onOpen && (
        <button type="button" onClick={() => onOpen(f)}
          className="mt-4 inline-flex items-center gap-1.5 text-[13px] font-medium text-accent-text transition-[gap] hover:gap-2.5">
          View evidence <ArrowRight className="h-3.5 w-3.5" />
        </button>
      )}
    </article>
  );
}

/** Evidence items with their source plugin - used in finding explanations and process evidence. */
export function EvidenceList({ items }: { items: EvidenceItem[] }) {
  return (
    <ol className="space-y-2.5">
      {items.map((e, i) => (
        <li key={i} className="flex gap-3 rounded-xl border border-line bg-surface-2/50 p-3.5">
          <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-surface-3 text-[11px] font-semibold tabular text-ink-2">
            {String(i + 1).padStart(2, "0")}
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2 text-[13px] text-ink-2">
              <span className="font-medium">{e.description}</span>
              <SourceTag source={e.source} />
              {e.ref && <span className="font-mono text-[11px] text-faint">{e.ref}</span>}
            </div>
            <Mono className="mt-1.5 block text-ink">{e.value}</Mono>
          </div>
        </li>
      ))}
    </ol>
  );
}

/** Large titled evidence panel with a severity rail. */
export function EvidencePanel({ title, eyebrow, severity, children, actions, className }: {
  title: ReactNode; eyebrow?: ReactNode; severity?: Finding["severity"]; children: ReactNode; actions?: ReactNode; className?: string;
}) {
  return (
    <section className={cx("relative overflow-hidden rounded-2xl border border-line bg-surface shadow-card", className)}>
      {severity && <span aria-hidden className="absolute inset-y-0 left-0 w-1" style={{ background: SEV_VAR[severity] }} />}
      <div className="p-6 md:p-7">
        {eyebrow && <div className="mb-2 flex flex-wrap items-center gap-2 text-xs text-muted">{eyebrow}</div>}
        <h3 className="break-all font-mono text-[17px] font-semibold text-ink">{title}</h3>
        <div className="mt-5">{children}</div>
        {actions && <div className="mt-6 flex flex-wrap gap-2.5">{actions}</div>}
      </div>
    </section>
  );
}
