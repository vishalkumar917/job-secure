import {
  Bot,
  Clock,
  Cpu,
  FileText,
  Fingerprint,
  FolderSearch,
  HardDrive,
  LayoutDashboard,
  LifeBuoy,
  LogOut,
  MemoryStick,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  ScanSearch,
  Settings,
  ShieldAlert,
} from "lucide-react";
import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { useAuth } from "../../hooks/useAuth";
import { useActiveAnalysis } from "../../hooks/useShell";
import type { SystemStatus } from "../../types";
import { cx, Tooltip } from "../ui";
import { Logo } from "./Logo";

interface Item {
  to: string;
  label: string;
  icon: ReactNode;
  end?: boolean;
  disabled?: boolean;
}

function NavItem({ item, collapsed, onNavigate }: { item: Item; collapsed: boolean; onNavigate?: () => void }) {
  const cls = ({ isActive }: { isActive: boolean }) => cx(
    "group relative flex h-9 items-center gap-3 rounded-[10px] text-[14px] font-medium transition-colors duration-150 [&_svg]:h-[18px] [&_svg]:w-[18px] [&_svg]:shrink-0",
    collapsed ? "w-9 justify-center" : "px-3",
    item.disabled ? "pointer-events-none text-faint"
      : isActive ? "bg-accent-soft text-ink" : "text-ink-2 hover:bg-surface-2 hover:text-ink",
  );
  const link = (
    <NavLink to={item.to} end={item.end} className={cls} onClick={onNavigate} aria-disabled={item.disabled || undefined}
      tabIndex={item.disabled ? -1 : undefined} aria-label={collapsed ? item.label : undefined}>
      {({ isActive }) => (
        <>
          {isActive && !item.disabled && <span aria-hidden className="absolute -left-3 top-2 bottom-2 w-[3px] rounded-r-full bg-accent" />}
          <span className={cx(isActive && !item.disabled ? "text-accent-text" : "text-muted group-hover:text-ink-2")}>{item.icon}</span>
          {!collapsed && <span className="truncate">{item.label}</span>}
        </>
      )}
    </NavLink>
  );
  return <li>{collapsed ? <Tooltip content={item.disabled ? `${item.label} - open an analysis first` : item.label} side="right">{link}</Tooltip> : link}</li>;
}

function Group({ label, children, collapsed, meta }: { label: string; children: ReactNode; collapsed: boolean; meta?: ReactNode }) {
  return (
    <div className="mt-5 first:mt-0">
      {collapsed ? <div className="mx-auto mb-2 h-px w-6 bg-line" aria-hidden />
        : <div className="mb-2 flex items-center gap-2 px-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-faint">{label}{meta}</div>}
      <ul className={cx("space-y-0.5", collapsed && "flex flex-col items-center")}>{children}</ul>
    </div>
  );
}

export function Sidebar({ collapsed, onToggle, onNavigate, status, mobile }: {
  collapsed: boolean; onToggle?: () => void; onNavigate?: () => void; status?: SystemStatus; mobile?: boolean;
}) {
  const { user, logout } = useAuth();
  const active = useActiveAnalysis();
  const base = active ? `/analysis/${active.id}` : "/investigations";
  const noAnalysis = !active;

  const workspace: Item[] = [
    { to: "/", label: "Overview", icon: <LayoutDashboard />, end: true },
    { to: "/investigations", label: "Investigations", icon: <FolderSearch /> },
    { to: "/memory-images", label: "Memory Images", icon: <HardDrive /> },
  ];
  const analysis: Item[] = [
    { to: base, label: "Analysis Summary", icon: <ScanSearch />, end: true },
    { to: `${base}/processes`, label: "Processes", icon: <Cpu /> },
    { to: `${base}/memory`, label: "Memory Analysis", icon: <MemoryStick /> },
    { to: `${base}/network`, label: "Network", icon: <Network /> },
    { to: `${base}/iocs`, label: "IOCs", icon: <Fingerprint /> },
    { to: `${base}/findings`, label: "Findings", icon: <ShieldAlert /> },
    { to: `${base}/timeline`, label: "Timeline", icon: <Clock /> },
    { to: `${base}/assistant`, label: "AI Assistant", icon: <Bot /> },
    { to: `${base}/reports`, label: "Reports", icon: <FileText /> },
  ].map((i) => ({ ...i, disabled: noAnalysis }));
  const admin: Item[] = [
    { to: "/settings", label: "Settings", icon: <Settings /> },
    { to: "/help", label: "Help", icon: <LifeBuoy /> },
  ];

  const online = status?.volatility.available;
  const initials = (user?.full_name || user?.username || "?").split(/\s+/).map((s) => s[0]).join("").slice(0, 2).toUpperCase();

  return (
    <div className="flex h-full flex-col">
      <div className={cx("flex h-(--topbar-h) shrink-0 items-center border-b border-line", collapsed ? "justify-center px-2" : "justify-between px-5")}>
        {collapsed ? (
          <Tooltip content="Expand sidebar" side="right">
            <button onClick={onToggle} aria-label="Expand sidebar" className="rounded-xl transition-opacity hover:opacity-85"><Logo collapsed /></button>
          </Tooltip>
        ) : (
          <>
            <NavLink to="/" onClick={onNavigate} className="min-w-0 rounded-lg" aria-label="MemTrace home"><Logo /></NavLink>
            {onToggle && !mobile && (
              <button onClick={onToggle} aria-label="Collapse sidebar" title="Collapse sidebar ( [ )"
                className="rounded-lg p-1.5 text-muted transition-colors hover:bg-surface-2 hover:text-ink">
                <PanelLeftClose className="h-[18px] w-[18px]" />
              </button>
            )}
          </>
        )}
      </div>

      <nav aria-label="Main navigation" className={cx("flex-1 py-5", collapsed ? "overflow-visible px-2" : "overflow-y-auto px-4")}>
        <Group label="Workspace" collapsed={collapsed}>
          {workspace.map((i) => <NavItem key={i.to} item={i} collapsed={collapsed} onNavigate={onNavigate} />)}
        </Group>
        <Group label="Analysis" collapsed={collapsed}
          meta={active && <span className="ml-auto truncate rounded-md bg-surface-2 px-1.5 py-0.5 font-mono text-[10.5px] normal-case tracking-normal text-muted" title={`${active.case_number} - ${active.image}`}>{active.case_number} #{active.id}</span>}>
          {analysis.map((i) => <NavItem key={i.label} item={i} collapsed={collapsed} onNavigate={onNavigate} />)}
        </Group>
        {noAnalysis && !collapsed && (
          <p className="mt-2 px-3 text-xs leading-relaxed text-faint">Open an analysis from an investigation to enable these views.</p>
        )}
        <Group label="Administration" collapsed={collapsed}>
          {admin.map((i) => <NavItem key={i.to} item={i} collapsed={collapsed} onNavigate={onNavigate} />)}
        </Group>
      </nav>

      <div className={cx("shrink-0 space-y-3 border-t border-line", collapsed ? "px-2 py-4" : "px-4 py-3.5")}>
        {collapsed ? (
          <Tooltip content={online ? "Analysis engine online" : "Volatility 3 unavailable - demo mode only"} side="right" className="flex justify-center">
            <span className={cx("block h-2.5 w-2.5 rounded-full animate-pulse-ring", online ? "bg-good text-good" : "bg-sev-medium text-sev-medium")} />
          </Tooltip>
        ) : (
          <div className="flex items-center gap-2.5 rounded-xl border border-line bg-surface-2/60 px-3.5 py-2.5" title={status ? (online ? `Volatility ${status.volatility.version ?? "3"} · AI: ${status.ai.provider}` : "Demo mode still works") : undefined}>
            <span className={cx("h-2 w-2 shrink-0 rounded-full animate-pulse-ring", online ? "bg-good text-good" : status ? "bg-sev-medium text-sev-medium" : "bg-faint text-faint")} />
            <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-ink">{status ? (online ? "Analysis engine online" : "Engine unavailable") : "Checking engine..."}</span>
            {status && online && <span className="shrink-0 font-mono text-[11px] text-muted">v{status.volatility.version ?? "3"}</span>}
          </div>
        )}
        <div className={cx("flex items-center", collapsed ? "flex-col gap-3" : "gap-3")}>
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-accent-strong to-cyan text-[13px] font-semibold text-white" aria-hidden>{initials}</span>
          {!collapsed && (
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-medium text-ink">{user?.full_name || user?.username}</div>
              <div className="text-xs capitalize text-muted">{user?.role}</div>
            </div>
          )}
          <Tooltip content="Sign out" side={collapsed ? "right" : "top"}>
            <button onClick={logout} aria-label="Sign out" className="rounded-lg p-2 text-muted transition-colors hover:bg-surface-2 hover:text-ink">
              <LogOut className="h-4 w-4" />
            </button>
          </Tooltip>
        </div>
        {collapsed && onToggle && (
          <Tooltip content="Expand sidebar" side="right" className="flex justify-center">
            <button onClick={onToggle} aria-label="Expand sidebar" className="rounded-lg p-2 text-muted hover:bg-surface-2 hover:text-ink"><PanelLeftOpen className="h-4 w-4" /></button>
          </Tooltip>
        )}
      </div>
    </div>
  );
}
