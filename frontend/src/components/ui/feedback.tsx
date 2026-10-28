import { AlertOctagon, AlertTriangle, CheckCircle2, Info, Loader2, RefreshCw, SearchX, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";
import { Button, cx } from "./primitives";

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cx("h-4 w-4 animate-spin", className)} aria-hidden />;
}

/** Inline loading line - prefer the skeletons below for page content. */
export function Loading({ label = "Loading..." }: { label?: string }) {
  return (
    <div className="flex items-center gap-2.5 px-1 py-6 text-sm text-muted" role="status">
      <Spinner /> {label}
    </div>
  );
}

/* ------------------------------------------------------------------ skeletons */
export function Skeleton({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return <div className={cx("skeleton", className)} style={style} aria-hidden />;
}

function SkeletonWrap({ children, label, className }: { children: ReactNode; label: string; className?: string }) {
  return <div role="status" aria-label={label} className={className}>{children}<span className="sr-only">{label}</span></div>;
}

export function SkeletonText({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <SkeletonWrap label="Loading" className={cx("space-y-3", className)}>
      {Array.from({ length: lines }, (_, i) => <Skeleton key={i} className="h-3.5" style={{ width: `${92 - ((i * 17) % 40)}%` }} />)}
    </SkeletonWrap>
  );
}

export function SkeletonTable({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <SkeletonWrap label="Loading table">
      <div className="flex gap-6 border-b border-line px-6 py-4">
        {Array.from({ length: cols }, (_, i) => <Skeleton key={i} className="h-3 flex-1" style={{ maxWidth: i === 1 ? 220 : 110 }} />)}
      </div>
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="flex h-14 items-center gap-6 border-b border-line px-6 last:border-0">
          {Array.from({ length: cols }, (_, i) => <Skeleton key={i} className="h-3.5 flex-1" style={{ maxWidth: i === 1 ? 260 : 120, opacity: 1 - r * 0.08 }} />)}
        </div>
      ))}
    </SkeletonWrap>
  );
}

export function SkeletonCards({ count = 4, className }: { count?: number; className?: string }) {
  return (
    <SkeletonWrap label="Loading" className={cx("grid gap-5 sm:grid-cols-2 xl:grid-cols-4", className)}>
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="rounded-2xl border border-line bg-surface p-6 shadow-card">
          <Skeleton className="h-3 w-24" />
          <Skeleton className="mt-5 h-8 w-20" />
          <Skeleton className="mt-4 h-3 w-32" />
        </div>
      ))}
    </SkeletonWrap>
  );
}

export function SkeletonChart({ height = 240 }: { height?: number }) {
  return (
    <SkeletonWrap label="Loading chart" className="flex items-end gap-3 px-2" >
      {[55, 80, 40, 95, 65, 30, 70].map((h, i) => <Skeleton key={i} className="flex-1 rounded-t-md rounded-b-none" style={{ height: (height * h) / 100 }} />)}
    </SkeletonWrap>
  );
}

export function SkeletonTree() {
  return (
    <SkeletonWrap label="Loading process tree" className="space-y-3 p-2">
      {[0, 1, 2, 2, 3, 3, 1, 2].map((d, i) => (
        <div key={i} className="flex items-center gap-3" style={{ paddingLeft: d * 28 }}>
          <Skeleton className="h-2.5 w-2.5 rounded-full" />
          <Skeleton className="h-4" style={{ width: 120 + ((i * 37) % 90) }} />
          <Skeleton className="h-4 w-12" />
        </div>
      ))}
    </SkeletonWrap>
  );
}

export function SkeletonAI() {
  return (
    <SkeletonWrap label="Composing answer" className="space-y-4">
      <Skeleton className="h-4 w-1/3" />
      <SkeletonText lines={3} />
      <div className="grid gap-3 sm:grid-cols-3">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-16" />)}</div>
    </SkeletonWrap>
  );
}

/* ------------------------------------------------------------------ states */
export function EmptyState({ title, children, icon, action, compact }: {
  title: string; children?: ReactNode; icon?: ReactNode; action?: ReactNode; compact?: boolean;
}) {
  return (
    <div className={cx("flex flex-col items-center justify-center text-center", compact ? "px-6 py-10" : "px-6 py-16")}>
      <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-line bg-surface-2 text-muted [&_svg]:h-5 [&_svg]:w-5">
        {icon ?? <SearchX />}
      </div>
      <div className="text-[15px] font-semibold text-ink">{title}</div>
      {children && <div className="mt-1.5 max-w-md text-sm leading-relaxed text-muted">{children}</div>}
      {action && <div className="mt-6 flex flex-wrap justify-center gap-2.5">{action}</div>}
    </div>
  );
}

/** Error state with optional probable causes and recovery actions. */
export function ErrorState({ message, title = "Something went wrong", onRetry, causes, actions, compact }: {
  message: string; title?: string; onRetry?: () => void; causes?: string[]; actions?: ReactNode; compact?: boolean;
}) {
  if (compact) {
    return (
      <div role="alert" className="flex flex-wrap items-start gap-3 rounded-xl border border-sev-critical/30 bg-sev-critical/[0.06] px-4 py-3.5 text-sm">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-sev-critical-text" />
        <div className="min-w-0 flex-1 text-ink-2">{message}</div>
        {onRetry && <Button size="sm" onClick={onRetry} icon={<RefreshCw />}>Retry</Button>}
      </div>
    );
  }
  return (
    <div role="alert" className="rounded-2xl border border-sev-critical/25 bg-surface p-6 shadow-card md:p-8">
      <div className="flex flex-col gap-5 sm:flex-row sm:items-start">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-sev-critical/10 text-sev-critical-text">
          <AlertOctagon className="h-5 w-5" />
        </div>
        <div className="min-w-0 flex-1">
          <h3 className="text-lg font-semibold text-ink">{title}</h3>
          <p className="mt-1.5 break-words text-sm leading-relaxed text-ink-2">{message}</p>
          {causes && causes.length > 0 && (
            <div className="mt-5">
              <div className="mb-2 text-xs font-semibold uppercase tracking-[0.06em] text-muted">Possible causes</div>
              <ul className="space-y-1.5 text-sm text-ink-2">
                {causes.map((c) => <li key={c} className="flex gap-2.5"><span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-faint" />{c}</li>)}
              </ul>
            </div>
          )}
          {(onRetry || actions) && (
            <div className="mt-6 flex flex-wrap gap-2.5">
              {onRetry && <Button variant="primary" onClick={onRetry} icon={<RefreshCw />}>Retry</Button>}
              {actions}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function Notice({ tone = "info", title, children, action, className }: {
  tone?: "info" | "warn" | "danger" | "ok"; title?: ReactNode; children: ReactNode; action?: ReactNode; className?: string;
}) {
  const map = {
    info: ["border-accent/20 bg-accent-soft", <Info key="i" className="h-[18px] w-[18px] text-accent-text" />],
    warn: ["border-sev-medium/25 bg-sev-medium/[0.07]", <AlertTriangle key="w" className="h-[18px] w-[18px] text-sev-medium-text" />],
    danger: ["border-sev-critical/25 bg-sev-critical/[0.07]", <ShieldAlert key="d" className="h-[18px] w-[18px] text-sev-critical-text" />],
    ok: ["border-good/25 bg-good/[0.07]", <CheckCircle2 key="o" className="h-[18px] w-[18px] text-good-text" />],
  } as const;
  return (
    <div className={cx("flex items-start gap-3 rounded-xl border px-4 py-3.5 text-sm leading-relaxed text-ink-2", map[tone][0], className)}>
      <span className="mt-0.5 shrink-0">{map[tone][1]}</span>
      <div className="min-w-0 flex-1">
        {title && <div className="mb-0.5 font-semibold text-ink">{title}</div>}
        {children}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

/** Mandatory label on every view of synthetic data. */
export function DemoBanner() {
  return (
    <div role="note" className="flex items-center justify-center gap-2 bg-sev-critical px-4 py-2 text-center text-[11.5px] font-bold uppercase tracking-[0.12em] text-white">
      <AlertOctagon className="h-3.5 w-3.5" aria-hidden />
      Demo data &mdash; not real forensic evidence
    </div>
  );
}
