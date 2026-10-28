import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";

export type ThemePref = "light" | "dark" | "system";
export type ResolvedTheme = "light" | "dark";

const KEY = "memtrace.theme";
const media = () => window.matchMedia("(prefers-color-scheme: dark)");

function readPref(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" || v === "system" ? v : "system";
  } catch {
    return "system";
  }
}

interface ThemeCtx {
  pref: ThemePref;
  resolved: ResolvedTheme;
  setPref: (p: ThemePref) => void;
}

const Ctx = createContext<ThemeCtx | null>(null);

/** Light / dark / system theme. The preference persists in localStorage; "system" follows the OS live. */
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [pref, setPrefState] = useState<ThemePref>(readPref);
  const [systemDark, setSystemDark] = useState(() => media().matches);
  const first = useRef(true);
  const resolved: ResolvedTheme = pref === "system" ? (systemDark ? "dark" : "light") : pref;

  useEffect(() => {
    const mq = media();
    const on = (e: MediaQueryListEvent) => setSystemDark(e.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    if (!first.current) {
      root.classList.add("theme-switching");
      window.setTimeout(() => root.classList.remove("theme-switching"), 320);
    }
    first.current = false;
    root.setAttribute("data-theme", resolved);
    root.style.colorScheme = resolved;
  }, [resolved]);

  const setPref = useCallback((p: ThemePref) => {
    setPrefState(p);
    try {
      localStorage.setItem(KEY, p);
    } catch {
      /* storage unavailable: preference lasts for this session only */
    }
  }, []);

  return <Ctx.Provider value={{ pref, resolved, setPref }}>{children}</Ctx.Provider>;
}

export function useTheme(): ThemeCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useTheme must be used inside ThemeProvider");
  return c;
}

/** Concrete colours for SVG charts (Recharts needs real values). Mirrors the tokens in index.css. */
export const CHART_THEME = {
  dark: {
    grid: "#1d2531", axis: "#2a3443", tick: "#7f8a9c", label: "#b3bccb", surface: "#0f141d", cursor: "rgba(255,255,255,0.04)",
    series1: "#3987e5", series2: "#d95926", series3: "#199e70",
  },
  light: {
    grid: "#e8ecf2", axis: "#cfd6e1", tick: "#647085", label: "#384355", surface: "#ffffff", cursor: "rgba(16,24,40,0.04)",
    series1: "#2a78d6", series2: "#eb6834", series3: "#1baf7a",
  },
} as const;

export function useChartTheme() {
  return CHART_THEME[useTheme().resolved];
}
