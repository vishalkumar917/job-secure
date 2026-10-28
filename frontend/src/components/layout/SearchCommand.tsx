import { ArrowRight, Bot, Clock, Cpu, CornerDownLeft, FileText, Fingerprint, FolderSearch, HardDrive, LayoutDashboard, LifeBuoy, MemoryStick, Moon, Network, Search, Settings, ShieldAlert, Sun } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { useActiveAnalysis } from "../../hooks/useShell";
import { useTheme } from "../../hooks/useTheme";
import { api } from "../../services/api";
import { IOC_TYPE_LABEL } from "../../services/format";
import type { Case, Finding, IOC, Process, Report } from "../../types";
import { cx, Kbd, SeverityDot, Spinner } from "../ui";

interface Result {
  id: string;
  group: string;
  title: string;
  meta?: string;
  icon: ReactNode;
  run: () => void;
  keywords: string;
}

interface Data {
  cases: Case[];
  processes: Process[];
  findings: Finding[];
  iocs: IOC[];
  reports: Report[];
}

const GROUP_ORDER = ["Actions", "Pages", "Investigations", "Processes", "Findings", "IOCs", "Reports"];
const LIMIT = 6;

/** Ctrl/Cmd+K command palette - searches investigations and (for the active analysis) processes, findings, IOCs and reports. */
export function SearchCommand({ open, onClose }: { open: boolean; onClose: () => void }) {
  const nav = useNavigate();
  const active = useActiveAnalysis();
  const { resolved, setPref } = useTheme();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const [data, setData] = useState<Data | null>(null);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    setQ("");
    setSel(0);
    setLoading(true);
    const id = active?.id;
    const none = <T,>() => Promise.resolve([] as T[]);
    Promise.all([
      api.cases().catch(() => [] as Case[]),
      id ? api.processes(id).catch(() => [] as Process[]) : none<Process>(),
      id ? api.findings(id).catch(() => [] as Finding[]) : none<Finding>(),
      id ? api.iocs(id).catch(() => [] as IOC[]) : none<IOC>(),
      id ? api.reports(id).catch(() => [] as Report[]) : none<Report>(),
    ]).then(([cases, processes, findings, iocs, reports]) => setData({ cases, processes, findings, iocs, reports }))
      .finally(() => setLoading(false));
    window.setTimeout(() => inputRef.current?.focus(), 20);
  }, [open, active?.id]);

  const go = (to: string) => () => { onClose(); nav(to); };

  const results = useMemo<Result[]>(() => {
    const base = active ? `/analysis/${active.id}` : null;
    const pages: Result[] = [
      { id: "p-overview", group: "Pages", title: "Overview", icon: <LayoutDashboard />, run: go("/"), keywords: "overview dashboard home security" },
      { id: "p-inv", group: "Pages", title: "Investigations", icon: <FolderSearch />, run: go("/investigations"), keywords: "investigations cases" },
      { id: "p-img", group: "Pages", title: "Memory Images", icon: <HardDrive />, run: go("/memory-images"), keywords: "memory images evidence dumps" },
      ...(base ? [
        { id: "p-proc", group: "Pages", title: "Processes", meta: active!.case_number, icon: <Cpu />, run: go(`${base}/processes`), keywords: "processes tree" },
        { id: "p-mem", group: "Pages", title: "Memory Analysis", meta: active!.case_number, icon: <MemoryStick />, run: go(`${base}/memory`), keywords: "memory malfind injection vad" },
        { id: "p-net", group: "Pages", title: "Network", meta: active!.case_number, icon: <Network />, run: go(`${base}/network`), keywords: "network connections netscan" },
        { id: "p-ioc", group: "Pages", title: "IOC Explorer", meta: active!.case_number, icon: <Fingerprint />, run: go(`${base}/iocs`), keywords: "ioc indicators" },
        { id: "p-find", group: "Pages", title: "Findings", meta: active!.case_number, icon: <ShieldAlert />, run: go(`${base}/findings`), keywords: "findings detections rules" },
        { id: "p-tl", group: "Pages", title: "Timeline", meta: active!.case_number, icon: <Clock />, run: go(`${base}/timeline`), keywords: "timeline events" },
        { id: "p-ai", group: "Pages", title: "AI Assistant", meta: active!.case_number, icon: <Bot />, run: go(`${base}/assistant`), keywords: "ai assistant ask chat" },
        { id: "p-rep", group: "Pages", title: "Reports", meta: active!.case_number, icon: <FileText />, run: go(`${base}/reports`), keywords: "reports pdf export" },
      ] : []),
      { id: "p-set", group: "Pages", title: "Settings", icon: <Settings />, run: go("/settings"), keywords: "settings ai provider rules yara scoring" },
      { id: "p-help", group: "Pages", title: "Help & keyboard shortcuts", icon: <LifeBuoy />, run: go("/help"), keywords: "help shortcuts docs" },
    ];
    const actions: Result[] = [
      { id: "a-new", group: "Actions", title: "New investigation", icon: <ArrowRight />, run: go("/investigations/new"), keywords: "new create investigation case upload" },
      { id: "a-theme", group: "Actions", title: `Switch to ${resolved === "dark" ? "light" : "dark"} theme`, icon: resolved === "dark" ? <Sun /> : <Moon />,
        run: () => { setPref(resolved === "dark" ? "light" : "dark"); onClose(); }, keywords: "theme dark light mode appearance" },
    ];
    const d = data;
    const items: Result[] = [...actions, ...pages];
    if (d) {
      d.cases.forEach((c) => items.push({ id: `c${c.id}`, group: "Investigations", title: c.case_number, meta: c.title, icon: <FolderSearch />,
        run: go(`/investigations/${c.id}`), keywords: `${c.case_number} ${c.title} ${c.description}` }));
      if (base) {
        [...d.processes].sort((a, b) => b.risk_score - a.risk_score).forEach((p) => items.push({ id: `p${p.id}`, group: "Processes",
          title: `PID ${p.pid} - ${p.name}`, meta: p.risk_score ? `risk ${p.risk_score} ${p.risk_band}` : p.path ?? undefined, icon: <Cpu />,
          run: go(`${base}/processes/${p.pid}`), keywords: `${p.pid} ${p.name} ${p.path ?? ""} ${p.cmdline ?? ""}` }));
        d.findings.forEach((f) => items.push({ id: `f${f.id}`, group: "Findings", title: f.title, meta: f.process_name ? `${f.process_name} (${f.pid})` : f.rule_id,
          icon: <SeverityDot severity={f.severity} className="h-2.5 w-2.5" />, run: go(`${base}/findings?f=${f.id}`), keywords: `${f.title} ${f.rule_id} ${f.process_name ?? ""} ${f.pid ?? ""} ${f.severity}` }));
        d.iocs.forEach((i) => items.push({ id: `i${i.id}`, group: "IOCs", title: i.value, meta: IOC_TYPE_LABEL[i.ioc_type] ?? i.ioc_type, icon: <Fingerprint />,
          run: go(`${base}/iocs?q=${encodeURIComponent(i.value)}`), keywords: `${i.value} ${i.ioc_type} ${i.process_name ?? ""} ${i.pid ?? ""}` }));
        d.reports.forEach((r) => items.push({ id: `r${r.id}`, group: "Reports", title: `${r.report_format.toUpperCase()} report #${r.id}`, meta: r.generated_at.slice(0, 16).replace("T", " "),
          icon: <FileText />, run: go(`${base}/reports`), keywords: `report ${r.report_format} ${r.sha256}` }));
      }
    }
    const needle = q.trim().toLowerCase();
    const filtered = needle
      ? items.filter((r) => needle.split(/\s+/).every((w) => `${r.title} ${r.meta ?? ""} ${r.keywords}`.toLowerCase().includes(w)))
      : items.filter((r) => r.group === "Actions" || r.group === "Pages" || (r.group === "Investigations"));
    const out: Result[] = [];
    GROUP_ORDER.forEach((g) => out.push(...filtered.filter((r) => r.group === g).slice(0, needle ? LIMIT : g === "Investigations" ? 4 : 12)));
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, data, active, resolved]);

  useEffect(() => setSel(0), [q]);
  useEffect(() => {
    listRef.current?.querySelector(`[data-idx="${sel}"]`)?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
      else if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, results.length - 1)); }
      else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
      else if (e.key === "Enter") { e.preventDefault(); results[sel]?.run(); }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, results, sel, onClose]);

  if (!open) return null;
  let idx = -1;
  return createPortal(
    <div className="fixed inset-0 z-(--z-command) flex items-start justify-center px-4 pt-[10vh]">
      <div className="absolute inset-0 animate-fade-in bg-overlay backdrop-blur-[2px]" onClick={onClose} aria-hidden />
      <div role="dialog" aria-modal="true" aria-label="Search"
        className="relative flex max-h-[72vh] w-full max-w-2xl animate-scale-in flex-col overflow-hidden rounded-2xl border border-line bg-surface shadow-overlay">
        <div className="flex items-center gap-3 border-b border-line px-5">
          <Search className="h-5 w-5 shrink-0 text-muted" />
          <input ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} role="combobox" aria-expanded="true" aria-controls="cmd-list"
            aria-activedescendant={results[sel] ? `cmd-${results[sel].id}` : undefined}
            placeholder={active ? `Search ${active.case_number}: PIDs, processes, IOCs, findings...` : "Search investigations and pages..."}
            className="h-14 min-w-0 flex-1 bg-transparent text-[15px] text-ink placeholder:text-faint focus:outline-none" />
          {loading && <Spinner className="text-muted" />}
          <Kbd>Esc</Kbd>
        </div>
        <div ref={listRef} id="cmd-list" role="listbox" className="flex-1 overflow-y-auto p-2">
          {results.length === 0 && !loading && (
            <div className="px-4 py-12 text-center text-sm text-muted">No results for "<span className="text-ink">{q}</span>".
              {!active && <div className="mt-1 text-xs">Open an analysis to search its processes, IOCs and findings.</div>}
            </div>
          )}
          {GROUP_ORDER.map((g) => {
            const rows = results.filter((r) => r.group === g);
            if (!rows.length) return null;
            return (
              <div key={g} className="mb-1" role="group" aria-label={g}>
                <div className="px-3 pb-1.5 pt-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-faint">{g}</div>
                {rows.map((r) => {
                  idx++;
                  const i = idx;
                  const on = i === sel;
                  return (
                    <button key={r.id} id={`cmd-${r.id}`} data-idx={i} role="option" aria-selected={on} onMouseMove={() => setSel(i)} onClick={r.run}
                      className={cx("flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left transition-colors [&_svg]:h-4 [&_svg]:w-4",
                        on ? "bg-accent-soft" : "hover:bg-surface-2")}>
                      <span className={cx("flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-line", on ? "bg-surface text-accent-text" : "bg-surface-2 text-muted")}>{r.icon}</span>
                      <span className="min-w-0 flex-1">
                        <span className={cx("block truncate text-sm font-medium", g === "IOCs" ? "font-mono text-[13px]" : "", "text-ink")}>{r.title}</span>
                        {r.meta && <span className="block truncate text-xs text-muted">{r.meta}</span>}
                      </span>
                      {on && <CornerDownLeft className="h-4 w-4 shrink-0 text-muted" />}
                    </button>
                  );
                })}
              </div>
            );
          })}
        </div>
        <div className="flex flex-wrap items-center gap-x-5 gap-y-1 border-t border-line px-5 py-2.5 text-xs text-muted">
          <span className="flex items-center gap-1.5"><Kbd>↑</Kbd><Kbd>↓</Kbd> navigate</span>
          <span className="flex items-center gap-1.5"><Kbd>Enter</Kbd> open</span>
          <span className="flex items-center gap-1.5"><Kbd>Esc</Kbd> close</span>
          {active && <span className="ml-auto">Scope: {active.case_number} · analysis #{active.id}</span>}
        </div>
      </div>
    </div>,
    document.body,
  );
}
