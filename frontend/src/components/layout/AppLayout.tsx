import {
  Activity,
  Bot,
  Clock,
  Cpu,
  FileText,
  Fingerprint,
  FolderSearch,
  LayoutDashboard,
  LogOut,
  MemoryStick,
  Network,
  Settings,
  ShieldAlert,
  Workflow,
} from "lucide-react";
import { createContext, useContext, type ReactNode } from "react";
import { NavLink, Outlet, useParams } from "react-router-dom";
import { useApi } from "../../hooks/useApi";
import { useAuth } from "../../hooks/useAuth";
import { api } from "../../services/api";
import type { JobDetail } from "../../types";
import { cx, DemoBanner, ErrorState, Loading, RiskBadge, StatusPill } from "../ui";

function SideLink({ to, icon, children, end }: { to: string; icon: ReactNode; children: ReactNode; end?: boolean }) {
  return (
    <NavLink to={to} end={end} className={({ isActive }) => cx(
      "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium",
      isActive ? "bg-accent/15 text-ink ring-1 ring-accent/30" : "text-ink-2 hover:bg-surface-2 hover:text-ink")}>
      <span className="text-muted">{icon}</span>{children}
    </NavLink>
  );
}

export function AppLayout() {
  const { user, logout } = useAuth();
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-line bg-surface px-3 py-4 md:flex">
        <div className="mb-6 flex items-center gap-2 px-2">
          <img src="/favicon.svg" alt="" className="h-8 w-8" />
          <div>
            <div className="text-sm font-bold tracking-wide text-ink">MemTrace</div>
            <div className="text-[11px] text-muted">Memory Forensics</div>
          </div>
        </div>
        <nav className="flex flex-col gap-1">
          <SideLink to="/" end icon={<LayoutDashboard className="h-4 w-4" />}>Dashboard</SideLink>
          <SideLink to="/investigations" icon={<FolderSearch className="h-4 w-4" />}>Investigations</SideLink>
          <SideLink to="/settings" icon={<Settings className="h-4 w-4" />}>Settings</SideLink>
        </nav>
        <div className="mt-auto rounded-lg border border-line p-3 text-xs text-muted">
          <div className="text-ink-2">{user?.full_name || user?.username}</div>
          <div className="capitalize">{user?.role}</div>
          <button onClick={logout} className="mt-2 inline-flex items-center gap-1 text-accent hover:underline"><LogOut className="h-3 w-3" />Sign out</button>
        </div>
      </aside>
      <div className="min-w-0 flex-1">
        <header className="flex items-center justify-between border-b border-line bg-surface px-4 py-2 md:hidden">
          <span className="font-bold">MemTrace</span>
          <nav className="flex gap-3 text-sm text-ink-2">
            <NavLink to="/">Dashboard</NavLink><NavLink to="/investigations">Cases</NavLink><NavLink to="/settings">Settings</NavLink>
          </nav>
        </header>
        <Outlet />
      </div>
    </div>
  );
}

export function Page({ children }: { children: ReactNode }) {
  return <main className="mx-auto w-full max-w-[1400px] px-4 py-6 md:px-6">{children}</main>;
}

/* ------------------------------------------------------------------ analysis section */
interface AnalysisCtx {
  job: JobDetail;
  jobId: number;
  reload: () => void;
}
const Ctx = createContext<AnalysisCtx | null>(null);

export function useAnalysis(): AnalysisCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useAnalysis outside AnalysisLayout");
  return c;
}

export function AnalysisLayout() {
  const { jobId: raw } = useParams();
  const jobId = Number(raw);
  const { data: job, error, loading, reload } = useApi(() => api.job(jobId), [jobId]);

  if (loading && !job) return <Page><Loading label="Loading analysis..." /></Page>;
  if (error || !job) return <Page><ErrorState message={error ?? "Analysis not found"} onRetry={reload} /></Page>;

  const base = `/analysis/${jobId}`;
  const done = job.status.startsWith("completed");
  const tabs: [string, string, ReactNode][] = [
    ["", "Overview", <Activity key="o" className="h-4 w-4" />],
    ["/processes", "Processes", <Cpu key="p" className="h-4 w-4" />],
    ["/memory", "Memory", <MemoryStick key="m" className="h-4 w-4" />],
    ["/network", "Network", <Network key="n" className="h-4 w-4" />],
    ["/iocs", "IOCs", <Fingerprint key="i" className="h-4 w-4" />],
    ["/findings", "Findings", <ShieldAlert key="f" className="h-4 w-4" />],
    ["/timeline", "Timeline", <Clock key="t" className="h-4 w-4" />],
    ["/assistant", "AI Assistant", <Bot key="a" className="h-4 w-4" />],
    ["/reports", "Reports", <FileText key="r" className="h-4 w-4" />],
    ["/progress", "Analysis log", <Workflow key="l" className="h-4 w-4" />],
  ];

  return (
    <Ctx.Provider value={{ job, jobId, reload }}>
      {job.image.is_demo && <DemoBanner />}
      <div className="border-b border-line bg-surface">
        <div className="mx-auto max-w-[1400px] px-4 pt-4 md:px-6">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
            <NavLink to={`/investigations/${job.case_id}`} className="text-muted hover:text-ink">{job.case_number}</NavLink>
            <span className="text-muted">/</span>
            <span className="truncate font-medium text-ink">{job.image.original_filename}</span>
            <span className="text-muted">Analysis #{job.id}</span>
            <StatusPill status={job.status} />
            {done && <RiskBadge score={job.overall_risk_score} band={job.overall_risk_band} />}
          </div>
          <nav className="mt-3 flex gap-1 overflow-x-auto">
            {tabs.map(([path, label, icon]) => {
              const disabled = !done && path !== "/progress";
              return (
                <NavLink key={path} to={disabled ? `${base}/progress` : base + path} end={path === ""}
                  aria-disabled={disabled}
                  className={({ isActive }) => cx("-mb-px flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-sm font-medium",
                    isActive ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink-2", disabled && "pointer-events-none opacity-40")}>
                  {icon}{label}
                </NavLink>
              );
            })}
          </nav>
        </div>
      </div>
      <Page><Outlet /></Page>
    </Ctx.Provider>
  );
}
