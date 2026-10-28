import { useId } from "react";
import { cx } from "../ui";

/** Brand mark: a memory module (pins) with a signal trace running through it. */
export function LogoMark({ className }: { className?: string }) {
  const id = useId();
  return (
    <svg viewBox="0 0 32 32" className={cx("h-9 w-9 shrink-0", className)} aria-hidden>
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#2a78d6" />
          <stop offset="1" stopColor="#1fb3c9" />
        </linearGradient>
      </defs>
      <rect width="32" height="32" rx="8" fill={`url(#${id})`} />
      <path d="M10 5.5v3M16 5.5v3M22 5.5v3M10 23.5v3M16 23.5v3M22 23.5v3" stroke="#fff" strokeOpacity=".45" strokeWidth="1.6" strokeLinecap="round" />
      <path d="M5.5 17h5.2l2.3-5.5 3.6 10 2.6-6.5 1.4 2h5.9" fill="none" stroke="#fff" strokeWidth="2.3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Logo({ collapsed, subtitle = true }: { collapsed?: boolean; subtitle?: boolean }) {
  return (
    <span className="flex min-w-0 items-center gap-3">
      <LogoMark />
      {!collapsed && (
        <span className="min-w-0">
          <span className="block text-[15px] font-semibold leading-tight tracking-[-0.01em] text-ink">MemTrace</span>
          {subtitle && <span className="block truncate text-xs leading-tight text-muted">AI-Powered Memory Forensics</span>}
        </span>
      )}
    </span>
  );
}
