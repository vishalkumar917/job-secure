import { useEffect, useState, useSyncExternalStore } from "react";

/* ------------------------------------------------------------------ active analysis
 * The analysis-scoped navigation (Processes, Network, ...) points at the analysis the investigator last
 * opened. Only display metadata is kept here; the analysis itself is always re-fetched from the API. */
export interface ActiveAnalysis {
  id: number;
  case_id: number;
  case_number: string;
  case_title: string;
  image: string;
  status: string;
  is_demo: boolean;
}

const KEY = "memtrace.activeAnalysis";
const listeners = new Set<() => void>();
let cache: ActiveAnalysis | null | undefined;

function read(): ActiveAnalysis | null {
  if (cache !== undefined) return cache;
  try {
    cache = JSON.parse(localStorage.getItem(KEY) ?? "null") as ActiveAnalysis | null;
  } catch {
    cache = null;
  }
  return cache;
}

export const activeAnalysisStore = {
  get: read,
  set(a: ActiveAnalysis | null) {
    const prev = read();
    if (JSON.stringify(prev) === JSON.stringify(a)) return;
    cache = a;
    try {
      if (a) localStorage.setItem(KEY, JSON.stringify(a));
      else localStorage.removeItem(KEY);
    } catch {
      /* storage unavailable */
    }
    listeners.forEach((l) => l());
  },
  subscribe(l: () => void) {
    listeners.add(l);
    return () => listeners.delete(l);
  },
};

export function useActiveAnalysis(): ActiveAnalysis | null {
  return useSyncExternalStore(activeAnalysisStore.subscribe, activeAnalysisStore.get);
}

/* ------------------------------------------------------------------ responsive helpers */
export function useMediaQuery(query: string): boolean {
  const [match, setMatch] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const mq = window.matchMedia(query);
    const on = () => setMatch(mq.matches);
    on();
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, [query]);
  return match;
}

/** Persisted boolean preference (e.g. sidebar collapsed). */
export function usePersistentFlag(key: string, initial: boolean): [boolean, (v: boolean) => void] {
  const [v, setV] = useState<boolean>(() => {
    try {
      const s = localStorage.getItem(key);
      return s == null ? initial : s === "1";
    } catch {
      return initial;
    }
  });
  const set = (next: boolean) => {
    setV(next);
    try {
      localStorage.setItem(key, next ? "1" : "0");
    } catch {
      /* ignore */
    }
  };
  return [v, set];
}

/** Re-render every `ms` so relative times ("2 minutes ago") and elapsed timers stay fresh. */
export function useNow(ms = 30000, active = true): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const id = window.setInterval(() => setNow(Date.now()), ms);
    return () => window.clearInterval(id);
  }, [ms, active]);
  return now;
}
