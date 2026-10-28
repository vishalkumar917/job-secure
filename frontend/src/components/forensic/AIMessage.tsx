import { ChevronRight, Copy, Cpu, ListChecks, ShieldCheck, Sparkles, TriangleAlert } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import type { Citation, Validation } from "../../types";
import { Badge, Button, cx, Markdown, parseAnswer } from "../ui";

const KIND_LABEL: Record<string, string> = {
  finding: "Findings", process: "Processes", network: "Network", memory: "Memory", module: "Modules", ioc: "IOCs",
  yara: "YARA", timeline: "Timeline", summary: "Summary",
};
const OPEN_BY_DEFAULT = new Set(["summary", "evidence", "interpretation"]);

export function ValidationBadge({ v }: { v: Partial<Validation> }) {
  if (!v.status) return null;
  const ok = v.status === "grounded";
  const detail = [...(v.warnings ?? []), ...(v.unsupported_entities ?? []).map((e) => `Unsupported: ${e}`), ...(v.overclaims ?? []).map((o) => `Over-claim: ${o}`)].join("\n");
  return (
    <span title={detail || undefined}>
      <Badge tone={ok ? "success" : "warning"} icon={ok ? <ShieldCheck /> : <TriangleAlert />}>
        {ok ? "Grounded in evidence" : `Validator: ${v.status}`}
      </Badge>
    </span>
  );
}

function Section({ title, index, children, defaultOpen }: { title: string; index: number; children: ReactNode; defaultOpen: boolean }) {
  return (
    <details open={defaultOpen} className="group/sec border-t border-line first:border-t-0">
      <summary className="flex cursor-pointer list-none items-center gap-3 py-3.5 text-sm font-semibold text-ink [&::-webkit-details-marker]:hidden">
        <span className="font-mono text-[11px] font-medium tabular text-faint">{String(index).padStart(2, "0")}</span>
        {title}
        <ChevronRight className="ml-auto h-4 w-4 text-muted transition-transform group-open/sec:rotate-90" />
      </summary>
      <div className="pb-4 pl-8">{children}</div>
    </details>
  );
}

/**
 * Structured rendering of an assistant answer. The answer text is grouped into sections exactly as written by
 * the engine (nothing is rewritten); confidence is derived from the response validator, sources from citations.
 */
export function AIMessage({ content, citations, validation, provider, onCite, actions, defaultCollapsed = false }: {
  content: string; citations: Citation[]; validation: Partial<Validation>; provider: string | null;
  onCite: (id: string) => void; actions?: ReactNode; defaultCollapsed?: boolean;
}) {
  const parsed = useMemo(() => parseAnswer(content), [content]);
  const [collapsed, setCollapsed] = useState(defaultCollapsed);
  const [showSources, setShowSources] = useState(false);
  const grounded = validation.status === "grounded";
  const byKind = useMemo(() => {
    const m = new Map<string, Citation[]>();
    citations.forEach((c) => m.set(c.kind, [...(m.get(c.kind) ?? []), c]));
    return [...m.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [citations]);
  const insufficient = /insufficient evidence/i.test(content) && content.length < 400;
  const hasConfidence = parsed.sections.some((s) => s.key === "confidence");

  return (
    <div className="min-w-0 flex-1 rounded-2xl border border-line bg-surface shadow-card">
      <div className="flex flex-wrap items-center gap-2.5 border-b border-line px-5 py-3.5 md:px-6">
        <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-accent-soft text-accent-text"><Sparkles className="h-4 w-4" /></span>
        <span className="text-sm font-semibold text-ink">Forensic AI</span>
        <ValidationBadge v={validation} />
        {provider && <span className="ml-auto inline-flex items-center gap-1.5 text-xs text-muted"><Cpu className="h-3.5 w-3.5" />{provider} engine</span>}
      </div>

      <div className="px-5 pt-4 md:px-6">
        {parsed.notice && (
          <div className="mb-4 rounded-lg border border-sev-critical/25 bg-sev-critical/[0.07] px-3.5 py-2.5 text-[13px] text-ink-2">
            <Markdown text={parsed.notice} onCite={onCite} className="!text-[13px] [&_p]:!m-0" />
          </div>
        )}
        {parsed.heading && <h3 className="mb-1 text-lg font-semibold tracking-[-0.01em] text-ink">{parsed.heading}</h3>}
        {collapsed ? (
          <div className="pb-4">
            {parsed.sections[0] && <Markdown text={parsed.sections[0].body.split(/\r?\n/).slice(0, 3).join("\n")} onCite={onCite} className="line-clamp-3" />}
            <Button size="sm" variant="subtle" className="mt-3" onClick={() => setCollapsed(false)}>Show full answer · {parsed.sections.length} sections</Button>
          </div>
        ) : insufficient ? (
          <div className="mb-4 flex items-start gap-3 rounded-xl border border-sev-medium/25 bg-sev-medium/[0.07] p-4 text-sm text-ink-2">
            <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-sev-medium-text" />
            <Markdown text={content} onCite={onCite} />
          </div>
        ) : (
          <div>
            {parsed.sections.map((s, i) => (
              <Section key={`${s.key}${i}`} title={s.title} index={i + 1} defaultOpen={OPEN_BY_DEFAULT.has(s.key) || parsed.sections.length <= 2}>
                <Markdown text={s.body} onCite={onCite} />
              </Section>
            ))}
            {!hasConfidence && (
              <Section title="Confidence" index={parsed.sections.length + 1} defaultOpen>
                <p className="text-sm leading-relaxed text-ink-2">
                  {grounded
                    ? <><span className="font-semibold text-ink">Validated.</span> Every PID, address, hash and binary named above was checked against {citations.length} cited evidence item{citations.length === 1 ? "" : "s"} from this analysis.</>
                    : <><span className="font-semibold text-sev-medium-text">Uncertain.</span> The response validator could not confirm every statement against stored evidence - treat unverified details with caution.</>}
                </p>
              </Section>
            )}
          </div>
        )}
      </div>

      {citations.length > 0 && !collapsed && (
        <div className="mx-5 mb-4 rounded-xl bg-surface-2/60 px-4 py-3 md:mx-6">
          <button type="button" onClick={() => setShowSources((s) => !s)} aria-expanded={showSources}
            className="flex w-full flex-wrap items-center gap-x-3 gap-y-2 text-left text-[13px] text-muted">
            <ListChecks className="h-4 w-4 text-ink-2" />
            <span className="font-medium text-ink-2">Sources</span>
            {byKind.map(([k, list]) => <span key={k}>{KIND_LABEL[k] ?? k} <span className="font-semibold tabular text-ink-2">{list.length}</span></span>)}
            <ChevronRight className={cx("ml-auto h-4 w-4 transition-transform", showSources && "rotate-90")} />
          </button>
          {showSources && (
            <ul className="mt-3 grid gap-1.5 border-t border-line pt-3 sm:grid-cols-2">
              {citations.map((c) => (
                <li key={c.id}>
                  <button type="button" onClick={() => onCite(c.id)} className="flex w-full items-center gap-2.5 rounded-lg px-2 py-1.5 text-left text-[13px] hover:bg-surface-3">
                    <span className="w-[72px] shrink-0 font-mono text-[11px] text-accent-text">{c.id}</span>
                    <span className="truncate text-ink-2">{c.title}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t border-line px-5 py-3 md:px-6">
        {actions}
        <Button size="sm" variant="ghost" icon={<Copy />} onClick={() => navigator.clipboard?.writeText(content)} className="ml-auto">Copy</Button>
      </div>
    </div>
  );
}
