import { Bot, CheckCircle2, Copy, FileClock, HardDrive, XCircle } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { Link, Navigate, Outlet, useLocation, useParams } from "react-router-dom";
import { useApi } from "../../hooks/useApi";
import { activeAnalysisStore, useMediaQuery, useNow, usePersistentFlag } from "../../hooks/useShell";
import { api } from "../../services/api";
import { fmtRelative } from "../../services/format";
import type { JobDetail, SystemStatus } from "../../types";
import { Button, cx, DemoBanner, ErrorState, RiskBadge, Skeleton, SkeletonCards, StatusPill, Tooltip } from "../ui";
import { CrumbCtx, useCrumbs, type Crumb } from "./crumbs";
import { SearchCommand } from "./SearchCommand";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

const isTyping = (e: KeyboardEvent) => {
  const t = e.target as HTMLElement | null;
  return !!t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable);
};

/* ------------------------------------------------------------------ application shell */
export function AppLayout() {
  const location = useLocation();
  const isLg = useMediaQuery("(min-width: 1024px)");
  const [prefCollapsed, setPrefCollapsed] = usePersistentFlag("memtrace.sidebarCollapsed", false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [crumbs, setCrumbs] = useState<Crumb[]>([]);
  const status = useApi<SystemStatus>(() => api.systemStatus(), []);
  const collapsed = prefCollapsed || !isLg;

  const toggleSidebar = useCallback(() => {
    if (isLg) setPrefCollapsed(!prefCollapsed);
    else setMobileOpen(true);
  }, [isLg, prefCollapsed, setPrefCollapsed]);

  useEffect(() => setMobileOpen(false), [location.pathname]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setSearchOpen((o) => !o);
      } else if (!isTyping(e) && !e.ctrlKey && !e.metaKey && !e.altKey) {
        if (e.key === "/") { e.preventDefault(); setSearchOpen(true); }
        else if (e.key === "[") toggleSidebar();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggleSidebar]);

  return (
    <CrumbCtx.Provider value={setCrumbs}>
      <a href="#main" className="sr-only z-(--z-toast) rounded-lg bg-surface px-4 py-2 text-ink focus:not-sr-only focus:fixed focus:left-4 focus:top-4">Skip to content</a>
      <aside aria-label="Sidebar"
        className={cx("fixed inset-y-0 left-0 z-(--z-sidebar) hidden border-r border-line bg-sidebar transition-[width] duration-300 ease-(--ease-out-soft) md:block",
          collapsed ? "w-(--sidebar-w-collapsed)" : "w-(--sidebar-w)")}>
        <Sidebar collapsed={collapsed} onToggle={toggleSidebar} status={status.data} />
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-(--z-overlay) md:hidden">
          <div className="absolute inset-0 animate-fade-in bg-overlay" onClick={() => setMobileOpen(false)} aria-hidden />
          <aside role="dialog" aria-modal="true" aria-label="Navigation"
            className="relative h-full w-[288px] max-w-[85vw] animate-slide-in-left border-r border-line bg-sidebar shadow-overlay">
            <Sidebar collapsed={false} mobile onNavigate={() => setMobileOpen(false)} status={status.data} />
          </aside>
        </div>
      )}

      <div className={cx("min-h-screen transition-[padding] duration-300 ease-(--ease-out-soft)", collapsed ? "md:pl-(--sidebar-w-collapsed)" : "md:pl-(--sidebar-w)")}>
        <TopBar crumbs={crumbs} onMenu={() => setMobileOpen(true)} onSearch={() => setSearchOpen(true)} status={status.data} />
        <div id="main" tabIndex={-1} className="outline-none">
          <Outlet />
        </div>
      </div>
      <SearchCommand open={searchOpen} onClose={() => setSearchOpen(false)} />
    </CrumbCtx.Provider>
  );
}

/** Top-level page container: max width, generous gutters, entrance transition. */
export function Page({ children, className, wide }: { children: ReactNode; className?: string; wide?: boolean }) {
  return (
    <main className={cx("mx-auto w-full animate-page-in px-5 py-8 sm:px-6 md:px-8 md:py-10 lg:px-10", wide ? "max-w-[1680px]" : "max-w-[1440px]", className)}>
      {children}
    </main>
  );
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

/** Breadcrumbs for a page inside an analysis: Investigations / CASE / Analysis #n / ...trail. */
export function useAnalysisCrumbs(...trail: Crumb[]) {
  const { job } = useAnalysis();
  useCrumbs([
    { label: "Investigations", to: "/investigations" },
    { label: job.case_number, to: `/investigations/${job.case_id}` },
    { label: `Analysis #${job.id}`, to: trail.length ? `/analysis/${job.id}` : undefined },
    ...trail,
  ]);
}

function shortHash(h: string) {
  return `${h.slice(0, 8)}…${h.slice(-6)}`;
}

function IntegrityTag({ job }: { job: JobDetail }) {
  const b = job.hash_verified_before, a = job.hash_verified_after;
  if (b == null) return null;
  const ok = b && a !== false;
  return (
    <Tooltip content={`SHA-256 re-verified before (${b ? "match" : "MISMATCH"}) and after (${a == null ? "pending" : a ? "match" : "MISMATCH"}) analysis`}>
      <span className={cx("inline-flex items-center gap-1.5 [&_svg]:h-3.5 [&_svg]:w-3.5", ok ? "text-good-text" : "text-sev-critical-text")}>
        {ok ? <CheckCircle2 /> : <XCircle />}{ok ? "Integrity verified" : "Integrity mismatch"}
      </span>
    </Tooltip>
  );
}

export function AnalysisLayout() {
  const { jobId: raw } = useParams();
  const jobId = Number(raw);
  const location = useLocation();
  const { data: job, error, loading, reload } = useApi(() => api.job(jobId), [jobId]);
  const now = useNow(30000);

  useEffect(() => {
    if (job && job.id === jobId) {
      activeAnalysisStore.set({ id: job.id, case_id: job.case_id, case_number: job.case_number, case_title: job.case_title,
        image: job.image.original_filename, status: job.status, is_demo: job.image.is_demo });
    }
  }, [job, jobId]);
  useEffect(() => {
    if (error && activeAnalysisStore.get()?.id === jobId) activeAnalysisStore.set(null);
  }, [error, jobId]);

  if (loading && !job) {
    return (
      <div className="mx-auto max-w-[1440px] px-5 py-10 md:px-8 lg:px-10">
        <Skeleton className="h-4 w-48" />
        <Skeleton className="mt-4 h-8 w-96 max-w-full" />
        <SkeletonCards className="mt-10" />
      </div>
    );
  }
  if (error || !job) {
    return (
      <Page>
        <ErrorState title="Analysis unavailable" message={error ?? "Analysis not found"} onRetry={reload}
          actions={<Button to="/investigations">Back to investigations</Button>} />
      </Page>
    );
  }

  const done = job.status.startsWith("completed");
  const onProgress = location.pathname.endsWith("/progress");
  if (!done && !onProgress) return <Navigate to={`/analysis/${jobId}/progress`} replace />;
  const os = job.image.os_info;

  return (
    <Ctx.Provider value={{ job, jobId, reload }}>
      {job.image.is_demo && <DemoBanner />}
      <div className="z-(--z-sticky) border-b border-line bg-page/85 backdrop-blur-xl md:sticky md:top-(--topbar-h)">
        <div className="mx-auto flex max-w-[1440px] flex-wrap items-center gap-x-6 gap-y-3 px-5 py-4 sm:px-6 md:px-8 lg:px-10">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <Link to={`/investigations/${job.case_id}`} className="rounded-md bg-surface-2 px-2 py-0.5 font-mono text-xs font-medium text-ink-2 ring-1 ring-line hover:text-ink">
                {job.case_number}
              </Link>
              <span className="truncate text-[15px] font-semibold text-ink">{job.case_title}</span>
              <StatusPill status={job.status} />
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[13px] text-muted">
              <span className="inline-flex min-w-0 items-center gap-1.5"><HardDrive className="h-3.5 w-3.5 shrink-0" /><span className="truncate">{job.image.original_filename}</span></span>
              <button type="button" onClick={() => navigator.clipboard?.writeText(job.image.sha256)} title={`SHA-256 ${job.image.sha256} (click to copy)`}
                className="hidden items-center gap-1 font-mono text-xs hover:text-ink sm:inline-flex">
                SHA-256 {shortHash(job.image.sha256)}<Copy className="h-3 w-3" />
              </button>
              {os?.os_name && <span className="hidden lg:inline">{os.os_name} {os.architecture ?? ""}</span>}
              <span>Analysis #{job.id} · {done ? `completed ${fmtRelative(job.completed_at, now)}` : `started ${fmtRelative(job.started_at ?? job.created_at, now)}`}</span>
              <IntegrityTag job={job} />
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            {done && job.overall_risk_band && (
              <div className="flex items-center gap-2 rounded-xl border border-line bg-surface px-3 py-1.5 shadow-card">
                <span className="text-xs font-medium text-muted">Risk</span>
                <RiskBadge score={job.overall_risk_score} band={job.overall_risk_band} />
              </div>
            )}
            <Button size="sm" to={`/analysis/${jobId}/progress`} icon={<FileClock />} variant={onProgress ? "subtle" : "secondary"}>Analysis log</Button>
            {done && <Button size="sm" variant="primary" to={`/analysis/${jobId}/assistant`} icon={<Bot />}>Ask AI</Button>}
          </div>
        </div>
      </div>
      <Page key={location.pathname}><Outlet /></Page>
    </Ctx.Provider>
  );
}
