import { AlertTriangle, CheckCircle2, Info, X, XCircle } from "lucide-react";
import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";

export type ToastTone = "success" | "info" | "warning" | "error";

interface Toast {
  id: number;
  tone: ToastTone;
  title: string;
  description?: string;
}

type Push = (t: Omit<Toast, "id">) => void;
const Ctx = createContext<Push | null>(null);

const TONE = {
  success: { icon: CheckCircle2, cls: "text-good-text" },
  info: { icon: Info, cls: "text-accent-text" },
  warning: { icon: AlertTriangle, cls: "text-sev-medium-text" },
  error: { icon: XCircle, cls: "text-sev-critical-text" },
} as const;

/** App-wide toast notifications (bottom-right, polite live region, auto-dismiss). */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const seq = useRef(0);

  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const push = useCallback<Push>((t) => {
    const id = ++seq.current;
    setToasts((all) => [...all.slice(-3), { ...t, id }]);
    window.setTimeout(() => dismiss(id), t.tone === "error" ? 8000 : 4500);
  }, [dismiss]);

  return (
    <Ctx.Provider value={push}>
      {children}
      <div aria-live="polite" aria-atomic="false"
        className="pointer-events-none fixed inset-x-4 bottom-4 z-(--z-toast) flex flex-col items-end gap-2.5 sm:inset-x-auto sm:right-6 sm:bottom-6">
        {toasts.map((t) => {
          const { icon: Icon, cls } = TONE[t.tone];
          return (
            <div key={t.id} role={t.tone === "error" ? "alert" : "status"}
              className="pointer-events-auto flex w-full max-w-sm animate-toast-in items-start gap-3 rounded-xl border border-line bg-surface px-4 py-3.5 shadow-overlay sm:w-96">
              <Icon className={`mt-0.5 h-5 w-5 shrink-0 ${cls}`} aria-hidden />
              <div className="min-w-0 flex-1">
                <div className="text-sm font-semibold text-ink">{t.title}</div>
                {t.description && <div className="mt-0.5 text-[13px] leading-snug text-muted">{t.description}</div>}
              </div>
              <button onClick={() => dismiss(t.id)} aria-label="Dismiss notification"
                className="-mr-1 rounded-md p-1 text-muted transition-colors hover:bg-surface-2 hover:text-ink">
                <X className="h-4 w-4" />
              </button>
            </div>
          );
        })}
      </div>
    </Ctx.Provider>
  );
}

export function useToast(): Push {
  const c = useContext(Ctx);
  if (!c) throw new Error("useToast must be used inside ToastProvider");
  return c;
}
