import { Check, ChevronDown, Copy, Search, X } from "lucide-react";
import { Fragment, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { Link } from "react-router-dom";

export function cx(...c: (string | false | null | undefined)[]): string {
  return c.filter(Boolean).join(" ");
}

/* ------------------------------------------------------------------ buttons */
type Variant = "primary" | "secondary" | "ghost" | "danger" | "subtle";
type Size = "sm" | "md" | "lg";

const VARIANT: Record<Variant, string> = {
  primary: "bg-accent-strong text-white border-transparent shadow-sm hover:bg-accent active:bg-accent-strong",
  secondary: "bg-surface text-ink border-line shadow-card hover:bg-surface-2 hover:border-line-strong",
  ghost: "bg-transparent text-ink-2 border-transparent hover:bg-surface-2 hover:text-ink",
  danger: "bg-sev-critical text-white border-transparent shadow-sm hover:brightness-110",
  subtle: "bg-accent-soft text-accent-text border-transparent hover:bg-accent/15",
};
const SIZE: Record<Size, string> = {
  sm: "h-8 gap-1.5 rounded-lg px-3 text-[13px]",
  md: "h-10 gap-2 rounded-[10px] px-4 text-sm",
  lg: "h-11 gap-2 rounded-xl px-5 text-[15px]",
};

export interface ButtonProps {
  children?: ReactNode;
  onClick?: () => void;
  variant?: Variant;
  size?: Size;
  disabled?: boolean;
  type?: "button" | "submit";
  title?: string;
  className?: string;
  to?: string;
  icon?: ReactNode;
  "aria-label"?: string;
}

export function Button({ children, onClick, variant = "secondary", size = "md", disabled, type = "button", title, className, to, icon, ...rest }: ButtonProps) {
  const cls = cx("inline-flex shrink-0 items-center justify-center whitespace-nowrap border font-medium transition-[background-color,border-color,color,box-shadow,filter] duration-150",
    "disabled:pointer-events-none disabled:opacity-45 [&_svg]:h-4 [&_svg]:w-4 [&_svg]:shrink-0", VARIANT[variant], SIZE[size], className);
  const body = <>{icon}{children}</>;
  if (to && !disabled) return <Link to={to} className={cls} title={title} aria-label={rest["aria-label"]}>{body}</Link>;
  return <button type={type} title={title} onClick={onClick} disabled={disabled} className={cls} aria-label={rest["aria-label"]}>{body}</button>;
}

export function IconButton({ label, onClick, children, className, active, to }: {
  label: string; onClick?: () => void; children: ReactNode; className?: string; active?: boolean; to?: string;
}) {
  const cls = cx("inline-flex h-9 w-9 items-center justify-center rounded-[10px] text-ink-2 transition-colors hover:bg-surface-2 hover:text-ink [&_svg]:h-[18px] [&_svg]:w-[18px]",
    active && "bg-surface-2 text-ink", className);
  if (to) return <Link to={to} className={cls} aria-label={label} title={label}>{children}</Link>;
  return <button type="button" onClick={onClick} className={cls} aria-label={label} title={label}>{children}</button>;
}

/* ------------------------------------------------------------------ layout */
export function Card({ title, subtitle, actions, children, className, pad = true, icon, bodyClassName }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; pad?: boolean;
  icon?: ReactNode; bodyClassName?: string;
}) {
  const hasHeader = title || actions;
  return (
    <section className={cx("min-w-0 rounded-2xl border border-line bg-surface shadow-card", className)}>
      {hasHeader && (
        <header className={cx("flex flex-wrap items-start justify-between gap-x-4 gap-y-3 px-6 pt-5", pad ? "pb-1" : "border-b border-line pb-5")}>
          <div className="flex min-w-0 items-start gap-3">
            {icon && <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-ink-2 [&_svg]:h-4 [&_svg]:w-4">{icon}</span>}
            <div className="min-w-0">
              {title && <h2 className="text-base font-semibold tracking-[-0.005em] text-ink">{title}</h2>}
              {subtitle && <p className="mt-0.5 text-[13px] leading-relaxed text-muted">{subtitle}</p>}
            </div>
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cx(pad && "p-6", pad && !!hasHeader && "pt-4", bodyClassName)}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions, eyebrow, meta }: {
  title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode; meta?: ReactNode;
}) {
  return (
    <div className="mb-8 flex flex-wrap items-end justify-between gap-x-6 gap-y-4">
      <div className="min-w-0 max-w-3xl">
        {eyebrow && <div className="mb-2 text-xs font-semibold uppercase tracking-[0.08em] text-accent-text">{eyebrow}</div>}
        <h1 className="text-[26px] font-semibold leading-tight tracking-[-0.02em] text-ink md:text-[30px]">{title}</h1>
        {subtitle && <p className="mt-2 text-[15px] leading-relaxed text-muted">{subtitle}</p>}
        {meta && <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-[13px] text-muted">{meta}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2.5">{actions}</div>}
    </div>
  );
}

export function SectionHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h2 className="text-lg font-semibold tracking-[-0.01em] text-ink md:text-xl">{title}</h2>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ forms */
export const inputCls =
  "h-10 w-full rounded-[10px] border border-line bg-surface px-3.5 text-sm text-ink shadow-card placeholder:text-faint transition-[border-color,box-shadow] duration-150 hover:border-line-strong focus:border-accent focus:outline-none focus:ring-4 focus:ring-accent/15 disabled:opacity-60";

export const textareaCls = cx(inputCls, "h-auto py-2.5 leading-relaxed");

export function Field({ label, children, hint, error, optional }: { label: string; children: ReactNode; hint?: ReactNode; error?: string; optional?: boolean }) {
  return (
    <label className="block">
      <span className="mb-2 flex items-baseline gap-2 text-[13px] font-medium text-ink-2">
        {label}{optional && <span className="text-xs font-normal text-faint">Optional</span>}
      </span>
      {children}
      {error ? <span className="mt-1.5 block text-xs text-sev-critical-text">{error}</span>
        : hint && <span className="mt-1.5 block text-xs leading-relaxed text-muted">{hint}</span>}
    </label>
  );
}

export function Select({ value, onChange, children, label, className }: {
  value: string | number; onChange: (v: string) => void; children: ReactNode; label: string; className?: string;
}) {
  return (
    <span className={cx("relative inline-flex", className)}>
      <select value={value} onChange={(e) => onChange(e.target.value)} aria-label={label}
        className={cx(inputCls, "w-full cursor-pointer appearance-none pr-9")}>
        {children}
      </select>
      <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
    </span>
  );
}

export function SearchInput({ value, onChange, placeholder = "Search...", className, label }: {
  value: string; onChange: (v: string) => void; placeholder?: string; className?: string; label?: string;
}) {
  return (
    <span className={cx("relative inline-flex w-full", className)}>
      <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
      <input className={cx(inputCls, "pl-10 pr-9")} placeholder={placeholder} value={value} aria-label={label ?? placeholder}
        onChange={(e) => onChange(e.target.value)} />
      {value && (
        <button type="button" onClick={() => onChange("")} aria-label="Clear search"
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-1 text-muted hover:bg-surface-2 hover:text-ink">
          <X className="h-3.5 w-3.5" />
        </button>
      )}
    </span>
  );
}

export function Switch({ checked, onChange, label, disabled, description }: {
  checked: boolean; onChange: (v: boolean) => void; label: ReactNode; disabled?: boolean; description?: ReactNode;
}) {
  return (
    <label className={cx("flex cursor-pointer items-start gap-3", disabled && "cursor-not-allowed opacity-60")}>
      <button type="button" role="switch" aria-checked={checked} disabled={disabled} onClick={() => onChange(!checked)}
        className={cx("relative mt-0.5 inline-flex h-[22px] w-[38px] shrink-0 rounded-full border transition-colors duration-200",
          checked ? "border-transparent bg-accent-strong" : "border-line-strong bg-surface-3")}>
        <span className={cx("absolute top-[2px] h-4 w-4 rounded-full bg-white shadow-sm transition-transform duration-200",
          checked ? "translate-x-[18px]" : "translate-x-[2px]")} />
      </button>
      <span className="min-w-0">
        <span className="block text-sm font-medium text-ink">{label}</span>
        {description && <span className="mt-0.5 block text-[13px] leading-relaxed text-muted">{description}</span>}
      </span>
    </label>
  );
}

/** Horizontal filter row that wraps on small screens. */
export function FilterBar({ children, right, className }: { children: ReactNode; right?: ReactNode; className?: string }) {
  return (
    <div className={cx("flex flex-wrap items-center gap-3", className)}>
      {children}
      {right && <div className="ml-auto flex items-center gap-3 text-[13px] text-muted">{right}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ tabs */
export function Tabs<T extends string>({ tabs, value, onChange, className }: {
  tabs: { key: T; label: ReactNode; count?: number; icon?: ReactNode }[]; value: T; onChange: (v: T) => void; className?: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKey = (e: KeyboardEvent, i: number) => {
    const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!d) return;
    e.preventDefault();
    const n = (i + d + tabs.length) % tabs.length;
    refs.current[n]?.focus();
    onChange(tabs[n].key);
  };
  return (
    <div className={cx("mb-6 flex gap-1 overflow-x-auto border-b border-line", className)} role="tablist">
      {tabs.map((t, i) => {
        const on = value === t.key;
        return (
          <button key={t.key} ref={(el) => { refs.current[i] = el; }} role="tab" aria-selected={on} tabIndex={on ? 0 : -1}
            onClick={() => onChange(t.key)} onKeyDown={(e) => onKey(e, i)}
            className={cx("relative -mb-px inline-flex shrink-0 items-center gap-2 px-3.5 pb-3 pt-1.5 text-sm font-medium transition-colors [&_svg]:h-4 [&_svg]:w-4",
              on ? "text-ink" : "text-muted hover:text-ink-2")}>
            {t.icon}{t.label}
            {t.count != null && (
              <span className={cx("rounded-full px-2 py-px text-[11px] font-semibold tabular", on ? "bg-accent-soft text-accent-text" : "bg-surface-2 text-muted")}>{t.count}</span>
            )}
            <span className={cx("absolute inset-x-2 -bottom-px h-0.5 rounded-full transition-colors", on ? "bg-accent" : "bg-transparent")} />
          </button>
        );
      })}
    </div>
  );
}

export function SegmentedControl<T extends string>({ options, value, onChange, label }: {
  options: { key: T; label: ReactNode; icon?: ReactNode }[]; value: T; onChange: (v: T) => void; label: string;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-[10px] border border-line bg-surface-2 p-1">
      {options.map((o) => (
        <button key={o.key} role="radio" aria-checked={value === o.key} onClick={() => onChange(o.key)}
          className={cx("inline-flex h-8 items-center gap-1.5 rounded-lg px-3 text-[13px] font-medium transition-all [&_svg]:h-4 [&_svg]:w-4",
            value === o.key ? "bg-surface text-ink shadow-card" : "text-muted hover:text-ink-2")}>
          {o.icon}{o.label}
        </button>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ small data display */
export function KeyValue({ rows, cols = 1 }: { rows: [ReactNode, ReactNode][]; cols?: 1 | 2 }) {
  return (
    <dl className={cx("grid gap-x-8 gap-y-4", cols === 2 && "sm:grid-cols-2")}>
      {rows.map(([k, v], i) => (
        <Fragment key={i}>
          <div className="min-w-0">
            <dt className="mb-1 text-xs font-medium uppercase tracking-[0.06em] text-muted">{k}</dt>
            <dd className="min-w-0 break-words text-sm text-ink">{v ?? <span className="text-faint">Unknown</span>}</dd>
          </div>
        </Fragment>
      ))}
    </dl>
  );
}

export function Mono({ children, className, title, nowrap }: { children: ReactNode; className?: string; title?: string; nowrap?: boolean }) {
  return <code title={title} className={cx("font-mono text-[12.5px] text-ink-2", nowrap ? "whitespace-nowrap" : "break-all", className)}>{children}</code>;
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded-md border border-line-strong bg-surface-2 px-1.5 font-sans text-[11px] font-medium text-muted">{children}</kbd>;
}

export function Divider({ className }: { className?: string }) {
  return <hr className={cx("border-line", className)} />;
}

export function CopyButton({ text, label = "Copy", compact }: { text: string; label?: string; compact?: boolean }) {
  const [done, setDone] = useState(false);
  const copy = () => navigator.clipboard?.writeText(text).then(() => {
    setDone(true);
    window.setTimeout(() => setDone(false), 1400);
  });
  return (
    <button type="button" onClick={(e) => { e.stopPropagation(); copy(); }} aria-label={`${label}: ${text.slice(0, 40)}`}
      className={cx("inline-flex items-center gap-1 rounded-md text-xs font-medium text-muted transition-colors hover:bg-surface-2 hover:text-ink",
        compact ? "p-1" : "px-1.5 py-1")}>
      {done ? <Check className="h-3.5 w-3.5 text-good-text" /> : <Copy className="h-3.5 w-3.5" />}
      {!compact && (done ? "Copied" : label)}
    </button>
  );
}

/** Accessible hover/focus tooltip (CSS only). */
export function Tooltip({ content, children, side = "top", className }: { content: ReactNode; children: ReactNode; side?: "top" | "right" | "bottom"; className?: string }) {
  const pos = {
    top: "bottom-full left-1/2 mb-2 -translate-x-1/2",
    bottom: "top-full left-1/2 mt-2 -translate-x-1/2",
    right: "left-full top-1/2 ml-3 -translate-y-1/2",
  }[side];
  return (
    <span className={cx("group/tt relative inline-flex", className)}>
      {children}
      <span role="tooltip"
        className={cx("pointer-events-none invisible absolute z-(--z-tooltip) w-max max-w-64 rounded-lg bg-ink px-2.5 py-1.5 text-xs font-medium leading-snug text-page opacity-0 shadow-raised transition-opacity duration-150",
          "group-hover/tt:visible group-hover/tt:opacity-100 group-focus-within/tt:visible group-focus-within/tt:opacity-100", pos)}>
        {content}
      </span>
    </span>
  );
}
