import { ChevronDown, ChevronRight, EyeOff, GitBranch, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import type { TreeNode } from "../../types";
import { BAND_COLOR, cx, inputCls } from "../ui";

/** Interactive process tree. Suspicious nodes are highlighted; branches containing risk auto-expand. */
export function ProcessTree({ roots, selectedPid, onSelect }: { roots: TreeNode[]; selectedPid?: number; onSelect: (n: TreeNode) => void }) {
  const [filter, setFilter] = useState("");
  const [onlyRisky, setOnlyRisky] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<number>>(() => {
    const s = new Set<number>();
    const walk = (n: TreeNode) => {
      if (n.subtree_risk === 0 && n.children.length > 3) s.add(n.id);
      n.children.forEach(walk);
    };
    roots.forEach(walk);
    return s;
  });

  const visible = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const keep = (n: TreeNode): TreeNode | null => {
      const kids = n.children.map(keep).filter(Boolean) as TreeNode[];
      const selfMatch = (!needle || n.name.toLowerCase().includes(needle) || String(n.pid) === needle)
        && (!onlyRisky || n.risk_score > 0 || n.hidden);
      return selfMatch || kids.length ? { ...n, children: kids } : null;
    };
    return roots.map(keep).filter(Boolean) as TreeNode[];
  }, [roots, filter, onlyRisky]);

  const toggle = (id: number) => setCollapsed((s) => {
    const n = new Set(s);
    if (n.has(id)) n.delete(id); else n.add(id);
    return n;
  });

  const render = (n: TreeNode, depth: number) => {
    const isOpen = !collapsed.has(n.id) || filter !== "" || onlyRisky;
    const risky = n.risk_score >= 30;
    return (
      <li key={n.id}>
        <div className={cx("group flex items-center gap-1.5 rounded-md py-1 pr-2 text-sm",
          selectedPid === n.pid ? "bg-accent/15 ring-1 ring-accent/40" : "hover:bg-surface-2")}
          style={{ paddingLeft: depth * 18 + 4 }}>
          {n.children.length ? (
            <button onClick={() => toggle(n.id)} className="text-muted hover:text-ink" aria-label={isOpen ? "Collapse" : "Expand"}>
              {isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            </button>
          ) : <span className="w-4" />}
          <button onClick={() => onSelect(n)} className="flex min-w-0 flex-1 items-center gap-2 text-left">
            <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: n.risk_score > 0 ? BAND_COLOR[n.risk_band] : "#343c4a" }} />
            <span className={cx("truncate", risky ? "font-semibold text-ink" : "text-ink-2", n.terminated && "line-through opacity-60")}>{n.name}</span>
            <span className="font-mono text-xs text-muted tabular">{n.pid}</span>
            {n.risk_score > 0 && <span className="text-xs font-semibold tabular" style={{ color: BAND_COLOR[n.risk_band] }}>{n.risk_score} {n.risk_band}</span>}
            {n.hidden && <span title="Found by psscan only - possible hidden process" className="inline-flex items-center gap-0.5 rounded bg-sev-critical/20 px-1 text-[10px] font-semibold text-[#f08a8a]"><EyeOff className="h-3 w-3" />hidden</span>}
            {n.anomalous_parent && <span title="Suspicious parent-child relationship" className="inline-flex items-center gap-0.5 rounded bg-sev-high/20 px-1 text-[10px] font-semibold text-sev-high"><GitBranch className="h-3 w-3" />parent</span>}
            {n.terminated && <span title="Terminated" className="inline-flex items-center gap-0.5 text-[10px] text-muted"><XCircle className="h-3 w-3" />exited</span>}
          </button>
        </div>
        {isOpen && n.children.length > 0 && <ul>{n.children.map((c) => render(c, depth + 1))}</ul>}
      </li>
    );
  };

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <input className={cx(inputCls, "max-w-xs")} placeholder="Filter by name or PID" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <label className="flex items-center gap-2 text-sm text-ink-2">
          <input type="checkbox" checked={onlyRisky} onChange={(e) => setOnlyRisky(e.target.checked)} className="accent-[#3987e5]" />
          Only suspicious branches
        </label>
        <span className="flex items-center gap-3 text-xs text-muted">
          {(["critical", "high", "moderate", "low"] as const).map((b) => (
            <span key={b} className="flex items-center gap-1"><span className="h-2 w-2 rounded-full" style={{ background: BAND_COLOR[b] }} />{b}</span>
          ))}
        </span>
      </div>
      <ul className="max-h-[70vh] overflow-auto rounded-lg border border-line bg-page/40 p-2 font-[450]">
        {visible.map((r) => render(r, 0))}
      </ul>
    </div>
  );
}
