import { ChevronDown, ChevronUp, Search } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { cx, EmptyState, inputCls } from "./index";

export interface Column<T> {
  key: string;
  header: string;
  render?: (row: T) => ReactNode;
  sortValue?: (row: T) => string | number | null | undefined;
  className?: string;
}

/** Searchable, sortable, paginated table. Search matches the joined text of all sort values. */
export function DataTable<T>({ rows, columns, rowKey, onRowClick, searchPlaceholder = "Search...", pageSize = 25,
  initialSort, toolbar, empty = "No rows", rowClassName }: {
  rows: T[]; columns: Column<T>[]; rowKey: (r: T) => string | number; onRowClick?: (r: T) => void;
  searchPlaceholder?: string; pageSize?: number; initialSort?: { key: string; dir: "asc" | "desc" };
  toolbar?: ReactNode; empty?: ReactNode; rowClassName?: (r: T) => string | undefined;
}) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState(initialSort);
  const [page, setPage] = useState(0);

  const valueOf = (c: Column<T>, r: T) => (c.sortValue ? c.sortValue(r) : (r as Record<string, unknown>)[c.key] as string | number | null);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    let out = needle
      ? rows.filter((r) => columns.some((c) => String(valueOf(c, r) ?? "").toLowerCase().includes(needle)))
      : rows;
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      if (col) {
        out = [...out].sort((a, b) => {
          const va = valueOf(col, a), vb = valueOf(col, b);
          if (va == null) return 1;
          if (vb == null) return -1;
          const cmp = typeof va === "number" && typeof vb === "number" ? va - vb : String(va).localeCompare(String(vb));
          return sort.dir === "asc" ? cmp : -cmp;
        });
      }
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, q, sort, columns]);

  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const current = Math.min(page, pages - 1);
  const visible = filtered.slice(current * pageSize, (current + 1) * pageSize);

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative w-full max-w-xs">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted" />
          <input className={cx(inputCls, "pl-8")} placeholder={searchPlaceholder} value={q}
            onChange={(e) => { setQ(e.target.value); setPage(0); }} aria-label="Search table" />
        </div>
        {toolbar}
        <span className="ml-auto text-xs text-muted tabular">{filtered.length} of {rows.length}</span>
      </div>
      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full text-left text-sm">
          <thead className="bg-surface-2 text-xs uppercase tracking-wide text-muted">
            <tr>
              {columns.map((c) => (
                <th key={c.key} className={cx("whitespace-nowrap px-3 py-2 font-medium", c.className)}>
                  <button className="inline-flex items-center gap-1 hover:text-ink" onClick={() =>
                    setSort((s) => ({ key: c.key, dir: s?.key === c.key && s.dir === "desc" ? "asc" : "desc" }))}>
                    {c.header}
                    {sort?.key === c.key && (sort.dir === "asc" ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />)}
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {visible.map((r) => (
              <tr key={rowKey(r)} onClick={onRowClick ? () => onRowClick(r) : undefined}
                className={cx(onRowClick && "cursor-pointer", "hover:bg-surface-2", rowClassName?.(r))}>
                {columns.map((c) => (
                  <td key={c.key} className={cx("px-3 py-2 align-top text-ink-2", c.className)}>
                    {c.render ? c.render(r) : String((r as Record<string, unknown>)[c.key] ?? "")}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {visible.length === 0 && <EmptyState title={typeof empty === "string" ? empty : "No rows"}>{typeof empty !== "string" && empty}</EmptyState>}
      </div>
      {pages > 1 && (
        <div className="mt-3 flex items-center justify-end gap-2 text-sm text-muted">
          <button className="rounded px-2 py-1 hover:bg-surface-2 disabled:opacity-40" disabled={current === 0} onClick={() => setPage(current - 1)}>Prev</button>
          <span className="tabular">{current + 1} / {pages}</span>
          <button className="rounded px-2 py-1 hover:bg-surface-2 disabled:opacity-40" disabled={current >= pages - 1} onClick={() => setPage(current + 1)}>Next</button>
        </div>
      )}
    </div>
  );
}
