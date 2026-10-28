import { ChevronRight } from "lucide-react";
import { createContext, useContext, useEffect, type ReactNode } from "react";
import { Link } from "react-router-dom";

export interface Crumb {
  label: string;
  to?: string;
}

type SetCrumbs = (c: Crumb[]) => void;
export const CrumbCtx = createContext<SetCrumbs>(() => {});

/** Pages declare their breadcrumb trail; the top bar renders it. */
export function useCrumbs(crumbs: Crumb[]) {
  const set = useContext(CrumbCtx);
  const key = JSON.stringify(crumbs);
  useEffect(() => {
    set(JSON.parse(key) as Crumb[]);
  }, [key, set]);
}

export function Breadcrumbs({ items, fallback }: { items: Crumb[]; fallback?: ReactNode }) {
  if (!items.length) return <>{fallback}</>;
  return (
    <nav aria-label="Breadcrumb" className="min-w-0">
      <ol className="flex min-w-0 items-center gap-1.5 text-sm">
        {items.map((c, i) => {
          const last = i === items.length - 1;
          return (
            <li key={`${c.label}${i}`} className={last ? "min-w-0" : "hidden shrink-0 items-center gap-1.5 sm:flex"}>
              {c.to && !last ? (
                <Link to={c.to} className="rounded-md px-1 py-0.5 text-muted transition-colors hover:text-ink">{c.label}</Link>
              ) : (
                <span aria-current={last ? "page" : undefined} className="block truncate px-1 font-medium text-ink">{c.label}</span>
              )}
              {!last && <ChevronRight className="h-3.5 w-3.5 text-faint" aria-hidden />}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
