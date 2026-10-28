import { X } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode, type RefObject } from "react";
import { createPortal } from "react-dom";
import { Button, cx } from "./primitives";

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

/** Escape to close, focus moved into the panel, Tab trapped inside, focus restored and body scroll locked. */
function useDialogBehaviour(open: boolean, onClose: () => void, panel: RefObject<HTMLElement | null>) {
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const t = window.setTimeout(() => {
      const el = panel.current;
      const target = el?.querySelector<HTMLElement>("[data-autofocus]") ?? el?.querySelector<HTMLElement>(FOCUSABLE) ?? el;
      target?.focus();
    }, 10);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        closeRef.current();
      } else if (e.key === "Tab" && panel.current) {
        const items = [...panel.current.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((x) => x.offsetParent !== null);
        if (!items.length) return;
        const first = items[0], last = items[items.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener("keydown", onKey);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.clearTimeout(t);
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = overflow;
      previous?.focus?.();
    };
  }, [open, panel]);
}

export function Modal({ open, onClose, title, description, children, footer, size = "md" }: {
  open: boolean; onClose: () => void; title: ReactNode; description?: ReactNode; children?: ReactNode; footer?: ReactNode;
  size?: "sm" | "md" | "lg";
}) {
  const ref = useRef<HTMLDivElement>(null);
  useDialogBehaviour(open, onClose, ref);
  if (!open) return null;
  const w = { sm: "max-w-md", md: "max-w-lg", lg: "max-w-3xl" }[size];
  return createPortal(
    <div className="fixed inset-0 z-(--z-modal) flex items-end justify-center p-4 sm:items-center">
      <div className="absolute inset-0 animate-fade-in bg-overlay backdrop-blur-[2px]" onClick={onClose} aria-hidden />
      <div ref={ref} role="dialog" aria-modal="true" aria-label={typeof title === "string" ? title : undefined} tabIndex={-1}
        className={cx("relative w-full animate-scale-in rounded-2xl border border-line bg-surface shadow-overlay outline-none", w)}>
        <div className="flex items-start justify-between gap-4 px-6 pt-6">
          <div className="min-w-0">
            <h2 className="text-lg font-semibold text-ink">{title}</h2>
            {description && <p className="mt-1 text-sm leading-relaxed text-muted">{description}</p>}
          </div>
          <button onClick={onClose} aria-label="Close dialog" className="-mr-2 -mt-1 rounded-lg p-1.5 text-muted transition-colors hover:bg-surface-2 hover:text-ink">
            <X className="h-5 w-5" />
          </button>
        </div>
        {children && <div className="px-6 pt-4 text-sm leading-relaxed text-ink-2">{children}</div>}
        <div className="flex flex-wrap justify-end gap-2.5 px-6 pb-6 pt-6">{footer}</div>
      </div>
    </div>,
    document.body,
  );
}

export function ConfirmDialog({ open, title, children, confirmLabel = "Confirm", danger, onConfirm, onCancel, busy }: {
  open: boolean; title: string; children: ReactNode; confirmLabel?: string; danger?: boolean;
  onConfirm: () => void; onCancel: () => void; busy?: boolean;
}) {
  return (
    <Modal open={open} onClose={onCancel} title={title} size="sm"
      footer={<>
        <Button onClick={onCancel}>Cancel</Button>
        <Button variant={danger ? "danger" : "primary"} onClick={onConfirm} disabled={busy}>{confirmLabel}</Button>
      </>}>
      {children}
    </Modal>
  );
}

export function Drawer({ open, title, subtitle, onClose, children, width = "lg", footer }: {
  open: boolean; title: ReactNode; subtitle?: ReactNode; onClose: () => void; children: ReactNode; width?: "md" | "lg" | "xl"; footer?: ReactNode;
}) {
  const ref = useRef<HTMLElement>(null);
  useDialogBehaviour(open, onClose, ref);
  if (!open) return null;
  const w = { md: "max-w-lg", lg: "max-w-2xl", xl: "max-w-4xl" }[width];
  return createPortal(
    <div className="fixed inset-0 z-(--z-overlay) flex justify-end">
      <div className="absolute inset-0 animate-fade-in bg-overlay" onClick={onClose} aria-hidden />
      <aside ref={ref} role="dialog" aria-modal="true" tabIndex={-1}
        className={cx("relative flex h-full w-full animate-slide-in-right flex-col border-l border-line bg-surface shadow-overlay outline-none", w)}>
        <header className="flex items-start justify-between gap-4 border-b border-line px-6 py-5 md:px-8">
          <div className="min-w-0">
            <div className="text-lg font-semibold leading-snug text-ink">{title}</div>
            {subtitle && <div className="mt-1 text-[13px] text-muted">{subtitle}</div>}
          </div>
          <button onClick={onClose} aria-label="Close panel" className="-mr-2 rounded-lg p-1.5 text-muted transition-colors hover:bg-surface-2 hover:text-ink">
            <X className="h-5 w-5" />
          </button>
        </header>
        <div className="flex-1 overflow-y-auto px-6 py-6 md:px-8">{children}</div>
        {footer && <footer className="flex flex-wrap justify-end gap-2.5 border-t border-line px-6 py-4 md:px-8">{footer}</footer>}
      </aside>
    </div>,
    document.body,
  );
}

/** Anchored dropdown panel; closes on outside click and Escape. */
export function Popover({ trigger, children, align = "right", width = "w-72", label }: {
  trigger: (props: { open: boolean; toggle: () => void }) => ReactNode; children: (close: () => void) => ReactNode;
  align?: "left" | "right"; width?: string; label: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);
  return (
    <div ref={ref} className="relative">
      {trigger({ open, toggle: () => setOpen((o) => !o) })}
      {open && (
        <div role="menu" aria-label={label}
          className={cx("absolute top-full z-(--z-command) mt-2 animate-scale-in overflow-hidden rounded-xl border border-line bg-surface shadow-overlay",
            align === "right" ? "right-0" : "left-0", width)}>
          {children(() => setOpen(false))}
        </div>
      )}
    </div>
  );
}

export function MenuItem({ children, onClick, icon, active, hint }: { children: ReactNode; onClick: () => void; icon?: ReactNode; active?: boolean; hint?: ReactNode }) {
  return (
    <button role="menuitem" onClick={onClick}
      className={cx("flex w-full items-center gap-3 px-3.5 py-2.5 text-left text-sm transition-colors hover:bg-surface-2 [&_svg]:h-4 [&_svg]:w-4",
        active ? "text-ink" : "text-ink-2")}>
      {icon && <span className={active ? "text-accent-text" : "text-muted"}>{icon}</span>}
      <span className="flex-1">{children}</span>
      {hint}
    </button>
  );
}
