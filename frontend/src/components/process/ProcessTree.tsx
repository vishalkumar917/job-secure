import { ChevronDown, ChevronRight, ChevronsDownUp, ChevronsUpDown, EyeOff, GitBranch, List, Maximize2, Minus, Network as GraphIcon, Plus, XCircle } from "lucide-react";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type PointerEvent as RPointerEvent } from "react";
import type { RiskBand, TreeNode } from "../../types";
import { BAND_COLOR, cx, SearchInput, SegmentedControl, Switch, Tooltip } from "../ui";

const NODE_W = 212;
const NODE_H = 46;
const COL_W = 264;
const ROW_H = 60;
const PAD = 28;

type Mode = "graph" | "list";

function defaultCollapsed(roots: TreeNode[]): Set<number> {
  const s = new Set<number>();
  const walk = (n: TreeNode) => {
    if (n.subtree_risk === 0 && n.children.length > 2) s.add(n.id);
    n.children.forEach(walk);
  };
  roots.forEach(walk);
  return s;
}

function countDescendants(n: TreeNode): number {
  return n.children.reduce((a, c) => a + 1 + countDescendants(c), 0);
}

const isRisky = (n: TreeNode) => n.risk_score > 0 || n.hidden;

/** Interactive process tree: zoom/pan graph or indented list. Suspicious nodes are highlighted; benign branches start collapsed. */
export function ProcessTree({ roots, selectedPid, onSelect, height = 620 }: {
  roots: TreeNode[]; selectedPid?: number; onSelect: (n: TreeNode) => void; height?: number;
}) {
  const [mode, setMode] = useState<Mode>("graph");
  const [filter, setFilter] = useState("");
  const [onlyRisky, setOnlyRisky] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<number>>(() => defaultCollapsed(roots));

  const visible = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const keep = (n: TreeNode): TreeNode | null => {
      const kids = n.children.map(keep).filter(Boolean) as TreeNode[];
      const selfMatch = (!needle || n.name.toLowerCase().includes(needle) || String(n.pid) === needle) && (!onlyRisky || isRisky(n));
      return selfMatch || kids.length ? { ...n, children: kids } : null;
    };
    return roots.map(keep).filter(Boolean) as TreeNode[];
  }, [roots, filter, onlyRisky]);

  const forceOpen = filter !== "" || onlyRisky;
  const isOpen = useCallback((n: TreeNode) => forceOpen || !collapsed.has(n.id), [forceOpen, collapsed]);
  const toggle = (id: number) => setCollapsed((s) => {
    const n = new Set(s);
    if (n.has(id)) n.delete(id); else n.add(id);
    return n;
  });
  const total = useMemo(() => roots.reduce((a, r) => a + 1 + countDescendants(r), 0), [roots]);

  return (
    <div>
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <SegmentedControl label="Tree view" value={mode} onChange={setMode}
          options={[{ key: "graph", label: "Graph", icon: <GraphIcon /> }, { key: "list", label: "List", icon: <List /> }]} />
        <SearchInput value={filter} onChange={setFilter} placeholder="Find process or PID" className="w-full sm:w-64" />
        <Switch checked={onlyRisky} onChange={setOnlyRisky} label={<span className="text-[13px]">Suspicious branches only</span>} />
        <div className="ml-auto flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
          {(["critical", "high", "moderate", "low"] as RiskBand[]).map((b) => (
            <span key={b} className="inline-flex items-center gap-1.5 capitalize"><span className="h-2 w-2 rounded-full" style={{ background: BAND_COLOR[b] }} />{b}</span>
          ))}
          <span className="tabular">{total} processes</span>
        </div>
      </div>
      {visible.length === 0 ? (
        <div className="rounded-xl border border-dashed border-line-strong px-6 py-16 text-center text-sm text-muted">No processes match the current filter.</div>
      ) : mode === "graph" ? (
        <GraphView roots={visible} isOpen={isOpen} toggle={toggle} selectedPid={selectedPid} onSelect={onSelect} height={height}
          expandAll={() => setCollapsed(new Set())} collapseBenign={() => setCollapsed(defaultCollapsed(roots))} />
      ) : (
        <ListView roots={visible} isOpen={isOpen} toggle={toggle} selectedPid={selectedPid} onSelect={onSelect} height={height} />
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ graph */
interface Placed {
  node: TreeNode;
  x: number;
  y: number;
  parent: Placed | null;
}

function layout(roots: TreeNode[], isOpen: (n: TreeNode) => boolean) {
  const out: Placed[] = [];
  let row = 0;
  const place = (n: TreeNode, depth: number, parent: Placed | null): Placed => {
    const p: Placed = { node: n, x: depth * COL_W, y: 0, parent };
    out.push(p);
    const kids = isOpen(n) ? n.children : [];
    if (!kids.length) {
      p.y = row++ * ROW_H;
    } else {
      const placed = kids.map((c) => place(c, depth + 1, p));
      p.y = (placed[0].y + placed[placed.length - 1].y) / 2;
    }
    return p;
  };
  roots.forEach((r) => place(r, 0, null));
  const width = Math.max(...out.map((p) => p.x)) + NODE_W;
  const height = Math.max(...out.map((p) => p.y)) + NODE_H;
  return { nodes: out, width, height };
}

function GraphView({ roots, isOpen, toggle, selectedPid, onSelect, height, expandAll, collapseBenign }: {
  roots: TreeNode[]; isOpen: (n: TreeNode) => boolean; toggle: (id: number) => void; selectedPid?: number; onSelect: (n: TreeNode) => void;
  height: number; expandAll: () => void; collapseBenign: () => void;
}) {
  const { nodes, width, height: h } = useMemo(() => layout(roots, isOpen), [roots, isOpen]);
  const box = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ x: PAD, y: PAD, k: 1 });
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);

  const fit = useCallback(() => {
    const el = box.current;
    if (!el) return;
    // Fit the width but never below a readable scale; tall trees are panned vertically.
    const k = Math.min(1, Math.max(0.85, (el.clientWidth - PAD * 2) / width));
    setView({ k, x: Math.max(PAD, (el.clientWidth - width * k) / 2), y: h * k < el.clientHeight - PAD * 2 ? (el.clientHeight - h * k) / 2 : PAD });
  }, [width, h]);

  // Fit on first render and when the filter changes the visible tree - not on every expand/collapse.
  const fitRef = useRef(fit);
  fitRef.current = fit;
  useLayoutEffect(() => { fitRef.current(); }, [roots]);

  const zoomAt = useCallback((factor: number, cx?: number, cy?: number) => {
    setView((v) => {
      const el = box.current;
      const px = cx ?? (el ? el.clientWidth / 2 : 0);
      const py = cy ?? (el ? el.clientHeight / 2 : 0);
      const k = Math.min(2, Math.max(0.3, v.k * factor));
      return { k, x: px - ((px - v.x) * k) / v.k, y: py - ((py - v.y) * k) / v.k };
    });
  }, []);

  // Wheel: pan; Ctrl/Cmd + wheel (or pinch): zoom around the cursor. Non-passive so the page does not scroll.
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      if (e.ctrlKey || e.metaKey) {
        const r = el.getBoundingClientRect();
        zoomAt(e.deltaY < 0 ? 1.1 : 1 / 1.1, e.clientX - r.left, e.clientY - r.top);
      } else {
        setView((v) => ({ ...v, x: v.x - e.deltaX, y: v.y - e.deltaY }));
      }
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [zoomAt]);

  const onDown = (e: RPointerEvent) => {
    if ((e.target as HTMLElement).closest("button")) return;
    drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y };
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  };
  const onMove = (e: RPointerEvent) => {
    const d = drag.current;
    if (!d) return;
    setView((v) => ({ ...v, x: d.vx + e.clientX - d.x, y: d.vy + e.clientY - d.y }));
  };
  const onUp = () => { drag.current = null; };

  const ctrl = "flex h-9 w-9 items-center justify-center text-ink-2 transition-colors hover:bg-surface-2 hover:text-ink [&_svg]:h-4 [&_svg]:w-4";
  return (
    <div className="relative overflow-hidden rounded-xl border border-line bg-surface-2/40" style={{ height }}>
      <div ref={box} className="canvas-grid absolute inset-0 cursor-grab touch-none select-none active:cursor-grabbing"
        onPointerDown={onDown} onPointerMove={onMove} onPointerUp={onUp} onPointerCancel={onUp}
        role="tree" aria-label="Process tree graph">
        <div className="absolute left-0 top-0 origin-top-left" style={{ transform: `translate(${view.x}px, ${view.y}px) scale(${view.k})`, width, height: h }}>
          <svg width={width} height={h} className="absolute inset-0 overflow-visible" aria-hidden>
            {nodes.filter((p) => p.parent).map((p) => {
              const a = p.parent!;
              const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2, x2 = p.x, y2 = p.y + NODE_H / 2, xm = x1 + (x2 - x1) / 2;
              const risky = p.node.subtree_risk > 0;
              return <path key={p.node.id} d={`M ${x1} ${y1} C ${xm} ${y1}, ${xm} ${y2}, ${x2} ${y2}`} fill="none"
                stroke={risky ? BAND_COLOR[p.node.risk_score > 0 ? p.node.risk_band : "low"] : "var(--color-line-strong)"}
                strokeOpacity={risky ? 0.55 : 1} strokeWidth={risky ? 1.75 : 1.25} />;
            })}
          </svg>
          {nodes.map(({ node: n, x, y }) => {
            const open = isOpen(n);
            const sel = selectedPid === n.pid;
            const color = n.risk_score > 0 ? BAND_COLOR[n.risk_band] : undefined;
            return (
              <div key={n.id} className="absolute" style={{ left: x, top: y, width: NODE_W, height: NODE_H }} role="treeitem" aria-selected={sel} aria-expanded={n.children.length ? open : undefined}>
                <button type="button" onClick={() => onSelect(n)} title={`${n.name} (PID ${n.pid})${n.path ? `\n${n.path}` : ""}`}
                  className={cx("flex h-full w-full items-center gap-2.5 rounded-xl border bg-surface px-3 text-left shadow-card transition-[border-color,box-shadow] duration-150 hover:shadow-raised",
                    sel ? "border-accent ring-4 ring-accent/20" : color ? "" : "border-line hover:border-line-strong", n.terminated && "opacity-60")}
                  style={color && !sel ? { borderColor: `color-mix(in oklab, ${color} 55%, transparent)`, background: `color-mix(in oklab, ${color} 7%, var(--color-surface))` } : undefined}>
                  <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: color ?? "var(--color-line-strong)" }} />
                  <span className="min-w-0 flex-1">
                    <span className={cx("block truncate text-[13px] leading-tight", color ? "font-semibold text-ink" : "font-medium text-ink-2", n.terminated && "line-through")}>{n.name}</span>
                    <span className="mt-0.5 flex items-center gap-1.5 text-[11px] text-muted">
                      <span className="font-mono tabular">{n.pid}</span>
                      {n.hidden && <EyeOff className="h-3 w-3 text-sev-critical-text" aria-label="hidden" />}
                      {n.anomalous_parent && <GitBranch className="h-3 w-3 text-sev-high-text" aria-label="anomalous parent" />}
                      {n.terminated && <XCircle className="h-3 w-3" aria-label="exited" />}
                    </span>
                  </span>
                  {n.risk_score > 0 && <span className="rounded-md px-1.5 py-0.5 text-[11px] font-bold tabular" style={{ color: "var(--color-ink)", background: `color-mix(in oklab, ${color} 22%, transparent)` }}>{n.risk_score}</span>}
                </button>
                {n.children.length > 0 && (
                  <button type="button" onClick={() => toggle(n.id)} aria-label={open ? `Collapse ${n.name}` : `Expand ${n.name} (${n.children.length} children)`}
                    className="absolute -right-3 top-1/2 flex h-6 min-w-6 -translate-y-1/2 items-center justify-center rounded-full border border-line-strong bg-surface px-1 text-[10px] font-semibold text-ink-2 shadow-card hover:border-accent hover:text-accent-text">
                    {open ? <Minus className="h-3 w-3" /> : `+${countDescendants(n)}`}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </div>
      <div className="absolute right-4 top-4 flex flex-col overflow-hidden rounded-xl border border-line bg-surface shadow-raised">
        <Tooltip content="Zoom in" side="bottom"><button className={ctrl} onClick={() => zoomAt(1.2)} aria-label="Zoom in"><Plus /></button></Tooltip>
        <Tooltip content="Zoom out" side="bottom"><button className={cx(ctrl, "border-t border-line")} onClick={() => zoomAt(1 / 1.2)} aria-label="Zoom out"><Minus /></button></Tooltip>
        <Tooltip content="Fit to view" side="bottom"><button className={cx(ctrl, "border-t border-line")} onClick={fit} aria-label="Fit to view"><Maximize2 /></button></Tooltip>
        <Tooltip content="Expand all" side="bottom"><button className={cx(ctrl, "border-t border-line")} onClick={expandAll} aria-label="Expand all"><ChevronsUpDown /></button></Tooltip>
        <Tooltip content="Collapse benign branches" side="bottom"><button className={cx(ctrl, "border-t border-line")} onClick={collapseBenign} aria-label="Collapse benign branches"><ChevronsDownUp /></button></Tooltip>
      </div>
      <div className="pointer-events-none absolute bottom-3 left-4 rounded-lg bg-surface/90 px-2.5 py-1 text-[11px] text-muted shadow-card">
        Drag or scroll to pan · Ctrl + scroll to zoom · {Math.round(view.k * 100)}%
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ list */
function ListView({ roots, isOpen, toggle, selectedPid, onSelect, height }: {
  roots: TreeNode[]; isOpen: (n: TreeNode) => boolean; toggle: (id: number) => void; selectedPid?: number; onSelect: (n: TreeNode) => void; height: number;
}) {
  const render = (n: TreeNode, depth: number) => {
    const open = isOpen(n);
    const color = n.risk_score > 0 ? BAND_COLOR[n.risk_band] : undefined;
    return (
      <li key={n.id} role="treeitem" aria-expanded={n.children.length ? open : undefined} aria-selected={selectedPid === n.pid}>
        <div className={cx("group relative flex min-h-11 items-center gap-2 rounded-lg pr-3 transition-colors",
          selectedPid === n.pid ? "bg-accent-soft ring-1 ring-accent/30" : "hover:bg-surface-2")} style={{ paddingLeft: depth * 24 + 8 }}>
          {depth > 0 && <span aria-hidden className="absolute bottom-0 top-0 w-px bg-line" style={{ left: depth * 24 - 6 }} />}
          {n.children.length ? (
            <button type="button" onClick={() => toggle(n.id)} className="rounded p-0.5 text-muted hover:bg-surface-3 hover:text-ink" aria-label={open ? "Collapse" : "Expand"}>
              {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            </button>
          ) : <span className="w-5" />}
          <button type="button" onClick={() => onSelect(n)} className="flex min-w-0 flex-1 items-center gap-3 py-2 text-left">
            <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: color ?? "var(--color-line-strong)" }} />
            <span className={cx("truncate text-sm", color ? "font-semibold text-ink" : "text-ink-2", n.terminated && "line-through opacity-60")}>{n.name}</span>
            <span className="font-mono text-xs tabular text-muted">{n.pid}</span>
            {!open && n.children.length > 0 && <span className="text-xs text-faint">+{countDescendants(n)}</span>}
            {n.risk_score > 0 && <span className="text-xs font-semibold tabular" style={{ color }}>{n.risk_score} <span className="font-medium capitalize">{n.risk_band}</span></span>}
            {n.hidden && <span title="Found by psscan only - possible hidden process" className="inline-flex items-center gap-1 rounded-md bg-sev-critical/10 px-1.5 py-0.5 text-[10.5px] font-semibold text-sev-critical-text"><EyeOff className="h-3 w-3" />hidden</span>}
            {n.anomalous_parent && <span title="Suspicious parent-child relationship" className="inline-flex items-center gap-1 rounded-md bg-sev-high/10 px-1.5 py-0.5 text-[10.5px] font-semibold text-sev-high-text"><GitBranch className="h-3 w-3" />parent</span>}
            {n.terminated && <span className="inline-flex items-center gap-1 text-[10.5px] text-muted"><XCircle className="h-3 w-3" />exited</span>}
          </button>
        </div>
        {open && n.children.length > 0 && <ul role="group">{n.children.map((c) => render(c, depth + 1))}</ul>}
      </li>
    );
  };
  return (
    <ul role="tree" aria-label="Process tree" className="overflow-auto rounded-xl border border-line bg-surface-2/30 p-2" style={{ maxHeight: height }}>
      {roots.map((r) => render(r, 0))}
    </ul>
  );
}
