import { Bell, CircleHelp, LogOut, Menu, Monitor, Moon, Search, Settings, Sun } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useApi, usePolling } from "../../hooks/useApi";
import { useAuth } from "../../hooks/useAuth";
import { useNow } from "../../hooks/useShell";
import { useTheme, type ThemePref } from "../../hooks/useTheme";
import { api } from "../../services/api";
import { fmtRelative, titleCase } from "../../services/format";
import type { SystemStatus } from "../../types";
import { cx, IconButton, Kbd, MenuItem, Popover, Spinner, StatusPill } from "../ui";
import { Breadcrumbs, type Crumb } from "./crumbs";

const SEEN_KEY = "memtrace.activitySeen";

/* ------------------------------------------------------------------ theme */
export function ThemeToggle() {
  const { pref, resolved, setPref } = useTheme();
  const opts: { key: ThemePref; label: string; icon: ReactNode }[] = [
    { key: "light", label: "Light", icon: <Sun /> },
    { key: "dark", label: "Dark", icon: <Moon /> },
    { key: "system", label: "System", icon: <Monitor /> },
  ];
  return (
    <Popover label="Theme" width="w-48" trigger={({ open, toggle }) => (
      <IconButton label={`Theme: ${pref}`} onClick={toggle} active={open}>{resolved === "dark" ? <Moon /> : <Sun />}</IconButton>
    )}>
      {(close) => (
        <div className="py-1.5">
          <div className="px-3.5 pb-1.5 pt-1 text-[11px] font-semibold uppercase tracking-[0.1em] text-faint">Appearance</div>
          {opts.map((o) => (
            <MenuItem key={o.key} icon={o.icon} active={pref === o.key} onClick={() => { setPref(o.key); close(); }}
              hint={pref === o.key ? <span className="h-1.5 w-1.5 rounded-full bg-accent" /> : undefined}>{o.label}</MenuItem>
          ))}
        </div>
      )}
    </Popover>
  );
}

/* ------------------------------------------------------------------ activity (real custody + job events) */
function Notifications() {
  const nav = useNavigate();
  const { data, reload } = useApi(() => api.dashboard(), []);
  const now = useNow(30000);
  usePolling(reload, 30000, true);
  const [seen, setSeen] = useState(() => {
    try { return Number(localStorage.getItem(SEEN_KEY) ?? 0); } catch { return 0; }
  });
  const running = (data?.recent_analyses ?? []).filter((a) => a.status === "running" || a.status === "queued");
  const events = data?.recent_custody ?? [];
  const unseen = events.filter((e) => new Date(e.timestamp).getTime() > seen).length + running.length;
  const markSeen = () => {
    const t = Date.now();
    setSeen(t);
    try { localStorage.setItem(SEEN_KEY, String(t)); } catch { /* ignore */ }
  };

  return (
    <Popover label="Activity" width="w-[min(92vw,380px)]" trigger={({ open, toggle }) => (
      <span className="relative">
        <IconButton label={`Activity${unseen ? ` (${unseen} new)` : ""}`} onClick={() => { if (!open) reload(); toggle(); }} active={open}><Bell /></IconButton>
        {unseen > 0 && <span className="pointer-events-none absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-sev-critical ring-2 ring-page" aria-hidden />}
      </span>
    )}>
      {(close) => (
        <div>
          <div className="flex items-center justify-between border-b border-line px-4 py-3">
            <span className="text-sm font-semibold text-ink">Activity</span>
            <button className="text-xs font-medium text-accent-text hover:underline" onClick={markSeen}>Mark all as read</button>
          </div>
          <div className="max-h-[420px] overflow-y-auto py-1">
            {running.map((a) => (
              <button key={`r${a.id}`} onClick={() => { close(); nav(`/analysis/${a.id}/progress`); }}
                className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-surface-2">
                <span className="mt-0.5 text-accent-text"><Spinner /></span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium text-ink">Analysis #{a.id} {a.status} - {a.progress}%</span>
                  <span className="block truncate text-xs text-muted">{a.case_number} · {a.image}</span>
                </span>
              </button>
            ))}
            {events.length === 0 && running.length === 0 && <div className="px-4 py-10 text-center text-sm text-muted">No activity yet.</div>}
            {events.map((e, i) => {
              const fresh = new Date(e.timestamp).getTime() > seen;
              return (
                <button key={i} onClick={() => { close(); nav(`/investigations/${e.case_id}`); }}
                  className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-surface-2">
                  <span className={cx("mt-1.5 h-2 w-2 shrink-0 rounded-full", fresh ? "bg-accent" : "bg-line-strong")} />
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm text-ink">{titleCase(e.action)} <span className="text-muted">by {e.actor}</span></span>
                    {e.details && <span className="block truncate text-xs text-muted">{e.details}</span>}
                    <span className="mt-0.5 block text-[11px] text-faint">{fmtRelative(e.timestamp, now)}</span>
                  </span>
                </button>
              );
            })}
          </div>
          <div className="border-t border-line px-4 py-2.5 text-xs text-muted">Chain-of-custody events across all investigations</div>
        </div>
      )}
    </Popover>
  );
}

/* ------------------------------------------------------------------ user */
function UserMenu() {
  const { user, logout } = useAuth();
  const nav = useNavigate();
  const initials = (user?.full_name || user?.username || "?").split(/\s+/).map((s) => s[0]).join("").slice(0, 2).toUpperCase();
  return (
    <Popover label="Account" width="w-60" trigger={({ toggle }) => (
      <button onClick={toggle} aria-label="Account menu"
        className="ml-1 flex h-9 w-9 items-center justify-center rounded-full bg-gradient-to-br from-accent-strong to-cyan text-[13px] font-semibold text-white ring-2 ring-transparent transition hover:ring-accent/30">
        {initials}
      </button>
    )}>
      {(close) => (
        <div className="py-1.5">
          <div className="border-b border-line px-4 pb-3 pt-2">
            <div className="text-sm font-semibold text-ink">{user?.full_name || user?.username}</div>
            <div className="text-xs capitalize text-muted">{user?.role} · {user?.username}</div>
          </div>
          <div className="py-1">
            <MenuItem icon={<Settings />} onClick={() => { close(); nav("/settings"); }}>Settings</MenuItem>
            <MenuItem icon={<CircleHelp />} onClick={() => { close(); nav("/help"); }}>Help & shortcuts</MenuItem>
            <MenuItem icon={<LogOut />} onClick={() => { close(); logout(); }}>Sign out</MenuItem>
          </div>
        </div>
      )}
    </Popover>
  );
}

/* ------------------------------------------------------------------ bar */
export function TopBar({ crumbs, onMenu, onSearch, status }: { crumbs: Crumb[]; onMenu: () => void; onSearch: () => void; status?: SystemStatus }) {
  const [mac, setMac] = useState(false);
  useEffect(() => setMac(/Mac|iPhone|iPad/.test(navigator.platform)), []);
  const online = status?.volatility.available;
  return (
    <header className="sticky top-0 z-(--z-header) flex h-(--topbar-h) items-center gap-3 border-b border-line bg-page/80 px-4 backdrop-blur-xl md:px-8">
      <IconButton label="Open navigation" onClick={onMenu} className="md:hidden"><Menu /></IconButton>
      <div className="min-w-0 flex-1"><Breadcrumbs items={crumbs} /></div>

      <button onClick={onSearch} aria-label="Search (Ctrl+K)"
        className="hidden h-9 w-64 items-center gap-2.5 rounded-[10px] border border-line bg-surface px-3 text-sm text-faint shadow-card transition-colors hover:border-line-strong hover:text-muted md:flex lg:w-72">
        <Search className="h-4 w-4" />
        <span className="flex-1 truncate text-left">Search cases, PIDs, IOCs...</span>
        <Kbd>{mac ? "⌘" : "Ctrl"}</Kbd><Kbd>K</Kbd>
      </button>
      <IconButton label="Search" onClick={onSearch} className="md:hidden"><Search /></IconButton>

      {status && (
        <span className="hidden items-center xl:flex">
          {online ? <StatusPill status="completed" label="Engine online" /> : <StatusPill status="completed_with_errors" label="Demo mode only" />}
        </span>
      )}
      <div className="flex items-center gap-1">
        <Notifications />
        <ThemeToggle />
        <IconButton label="Help" to="/help" className="hidden sm:inline-flex"><CircleHelp /></IconButton>
        <UserMenu />
      </div>
    </header>
  );
}
