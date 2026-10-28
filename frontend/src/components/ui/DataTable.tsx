import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, ChevronsUpDown } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { EmptyState, SkeletonTable } from "./feedback";
import { cx, SearchInput } from "./primitives";

export interface Column<T> {
  key: string;
  header: string;
  render?: (row: T) => ReactNode;
  sortValue?: (row: T) => string | number | null | undefined;
  className?: string;
  headerClassName?: string;
  sortable?: boolean;
  align?: "left" | "right";
}

/**
 * Searchable, sortable, paginated table. Rows are 56px+ with generous padding; the header is sticky inside the
 * scroll container; clickable rows are keyboard accessible. `rowAccent` paints a 3px severity rail on the row.
 * Search matches the text of every column's sort value.
 */
export function DataTable<T>({ rows, columns, rowKey, onRowClick, searchPlaceholder = "Search...", pageSize = 25,
  initialSort, toolbar, empty = "No results", rowClassName, rowAccent, loading, search = true, maxHeight, footer, initialSearch = "" }: {
  rows: T[]; columns: Column<T>[]; rowKey: (r: T) => string | number; onRowClick?: (r: T) => void;
  searchPlaceholder?: string; pageSize?: number; initialSort?: { key: string; dir: "asc" | "desc" };
  toolbar?: ReactNode; empty?: ReactNode; rowClassName?: (r: T) => string | undefined; rowAccent?: (r: T) => string | undefined;
  loading?: boolean; search?: boolean; maxHeight?: string; footer?: ReactNode; initialSearch?: string;
}) {
  const [q, setQ] = useState(initialSearch);
  const [sort, setSort] = useState(initialSort);
  const [page, setPage] = useState(0);

  const valueOf = (c: Column<T>, r: T) => (c.sortValue ? c.sortValue(r) : (r as Record<string, unknown>)[c.key] as string | number | null);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    let out = needle ? rows.filter((r) => columns.some((c) => String(valueOf(c, r) ?? "").toLowerCase().includes(needle))) : rows;
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      if (col) {
        out = [...out].sort((a, b) => {
          const va = valueOf(col, a), vb = valueOf(col, b);
          if (va == null) return 1;
          if (vb == null) return -1;
          const cmp = typeof va === "number" && typeof vb === "number" ? va - vb : String(va).localeCompare(String(vb), undefined, { numeric: true });
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
  const showToolbar = search || toolbar;

  const toggleSort = (c: Column<T>) => {
    if (c.sortable === false) return;
    setSort((s) => ({ key: c.key, dir: s?.key === c.key && s.dir === "desc" ? "asc" : "desc" }));
  };

  return (
    <div className="min-w-0">
      {showToolbar && (
        <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-4 md:px-6">
          {search && <SearchInput value={q} onChange={(v) => { setQ(v); setPage(0); }} placeholder={searchPlaceholder} className="w-full sm:max-w-xs" />}
          {toolbar}
          <span className="ml-auto whitespace-nowrap text-[13px] tabular text-muted">
            {filtered.length === rows.length ? `${rows.length} ${rows.length === 1 ? "item" : "items"}` : `${filtered.length} of ${rows.length}`}
          </span>
        </div>
      )}
      {loading ? <SkeletonTable cols={Math.min(columns.length, 6)} /> : (
        <div className="overflow-auto" style={maxHeight ? { maxHeight } : undefined}>
          <table className="w-full border-separate border-spacing-0 text-left text-sm">
            <thead>
              <tr>
                {columns.map((c, i) => {
                  const active = sort?.key === c.key;
                  return (
                    <th key={c.key} scope="col" aria-sort={active ? (sort!.dir === "asc" ? "ascending" : "descending") : undefined}
                      className={cx("sticky top-0 z-[1] whitespace-nowrap border-b border-line bg-surface-2/95 py-3 text-xs font-semibold uppercase tracking-[0.06em] text-muted backdrop-blur",
                        i === 0 ? "pl-5 pr-4 md:pl-6" : "px-4", i === columns.length - 1 && "pr-5 md:pr-6", c.align === "right" && "text-right", c.headerClassName)}>
                      {c.sortable === false ? c.header : (
                        <button type="button" onClick={() => toggleSort(c)}
                          className={cx("group inline-flex items-center gap-1.5 uppercase transition-colors hover:text-ink", active && "text-ink")}>
                          {c.header}
                          {active ? (sort!.dir === "asc" ? <ArrowUp className="h-3.5 w-3.5" /> : <ArrowDown className="h-3.5 w-3.5" />)
                            : <ChevronsUpDown className="h-3.5 w-3.5 opacity-0 transition-opacity group-hover:opacity-60" />}
                        </button>
                      )}
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {visible.map((r) => {
                const accent = rowAccent?.(r);
                return (
                  <tr key={rowKey(r)} onClick={onRowClick ? () => onRowClick(r) : undefined}
                    onKeyDown={onRowClick ? (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onRowClick(r); } } : undefined}
                    tabIndex={onRowClick ? 0 : undefined}
                    className={cx("group/row transition-colors hover:bg-surface-2/70", onRowClick && "cursor-pointer focus-visible:bg-surface-2 focus-visible:outline-none", rowClassName?.(r))}>
                    {columns.map((c, i) => (
                      <td key={c.key}
                        className={cx("border-b border-line py-4 align-middle text-ink-2", i === 0 ? "relative pl-5 pr-4 md:pl-6" : "px-4",
                          i === columns.length - 1 && "pr-5 md:pr-6", c.align === "right" && "text-right", c.className)}>
                        {i === 0 && accent && <span aria-hidden className="absolute inset-y-2 left-0 w-[3px] rounded-r-full" style={{ background: accent }} />}
                        {c.render ? c.render(r) : String((r as Record<string, unknown>)[c.key] ?? "")}
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
          {visible.length === 0 && (typeof empty === "string" ? <EmptyState title={empty} compact>{q ? "Try a different search term or clear the filters." : undefined}</EmptyState> : empty)}
        </div>
      )}
      {(pages > 1 || footer) && !loading && (
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 text-[13px] text-muted md:px-6">
          <div>{footer ?? <span className="tabular">Showing {current * pageSize + 1}-{Math.min((current + 1) * pageSize, filtered.length)} of {filtered.length}</span>}</div>
          {pages > 1 && (
            <nav className="flex items-center gap-1" aria-label="Pagination">
              <PageBtn disabled={current === 0} onClick={() => setPage(current - 1)} label="Previous page"><ChevronLeft className="h-4 w-4" /></PageBtn>
              {pageList(current, pages).map((p, i) => p < 0 ? <span key={`e${i}`} className="px-1.5">...</span> : (
                <PageBtn key={p} active={p === current} onClick={() => setPage(p)} label={`Page ${p + 1}`}>{p + 1}</PageBtn>
              ))}
              <PageBtn disabled={current >= pages - 1} onClick={() => setPage(current + 1)} label="Next page"><ChevronRight className="h-4 w-4" /></PageBtn>
            </nav>
          )}
        </div>
      )}
    </div>
  );
}

function pageList(cur: number, total: number): number[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i);
  const set = [0, total - 1, cur - 1, cur, cur + 1].filter((p) => p >= 0 && p < total);
  const sorted = [...new Set(set)].sort((a, b) => a - b);
  const out: number[] = [];
  sorted.forEach((p, i) => {
    if (i && p - sorted[i - 1] > 1) out.push(-1);
    out.push(p);
  });
  return out;
}

function PageBtn({ children, onClick, disabled, active, label }: { children: ReactNode; onClick: () => void; disabled?: boolean; active?: boolean; label: string }) {
  return (
    <button type="button" onClick={onClick} disabled={disabled} aria-label={label} aria-current={active ? "page" : undefined}
      className={cx("inline-flex h-8 min-w-8 items-center justify-center rounded-lg px-2 text-[13px] font-medium tabular transition-colors disabled:opacity-35",
        active ? "bg-accent-soft text-accent-text" : "text-ink-2 hover:bg-surface-2")}>
      {children}
    </button>
  );
}
