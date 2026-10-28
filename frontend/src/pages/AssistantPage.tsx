import { ArrowUp, Bot, ChevronRight, Cpu, Database, MessageSquareText, ShieldAlert, ShieldCheck, Sparkles } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { AIMessage } from "../components/forensic/AIMessage";
import { useCitationNav } from "../components/forensic/cite";
import { useAnalysis, useAnalysisCrumbs } from "../components/layout/AppLayout";
import { Button, Card, cx, ErrorState, RiskBadge, SkeletonAI } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { ChatMessage, Citation } from "../types";

const SUGGESTIONS = [
  "Which processes are most suspicious?",
  "Why is PID 4528 suspicious?",
  "What evidence suggests process injection?",
  "Show me suspicious parent-child relationships.",
  "What network connections belong to suspicious processes?",
  "Summarize the investigation.",
  "Generate an incident timeline.",
  "What additional evidence should an investigator examine?",
];

function firstPid(citations: Citation[]): number | null {
  const c = citations.find((x) => x.kind === "process" && x.pid != null) ?? citations.find((x) => x.pid != null);
  return c?.pid ?? null;
}

export default function AssistantPage() {
  const { job, jobId } = useAnalysis();
  useAnalysisCrumbs({ label: "AI Assistant" });
  const cite = useCitationNav(jobId);
  const history = useApi(() => api.aiHistory(jobId), [jobId]);
  const status = useApi(() => api.systemStatus(), []);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ msg: string; question: string } | null>(null);
  const endRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const base = `/analysis/${jobId}`;

  useEffect(() => { if (history.data) setMessages(history.data); }, [history.data]);
  useEffect(() => {
    if (messages.length || busy) endRef.current?.scrollIntoView({ block: "end", behavior: "smooth" });
  }, [messages.length, busy]);
  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, 180)}px`;
  }, [q]);

  const ask = async (question: string) => {
    const text = question.trim();
    if (!text || busy) return;
    setBusy(true);
    setError(null);
    setQ("");
    setMessages((m) => [...m, { id: -Date.now(), role: "user", content: text, citations: [], validation: {}, provider: null, created_at: new Date().toISOString() }]);
    try {
      const a = await api.aiQuery(jobId, text);
      setMessages((m) => [...m, { id: a.message_id ?? -Date.now() - 1, role: "assistant", content: a.answer, citations: a.citations,
        validation: a.validation, provider: a.provider, created_at: new Date().toISOString() }]);
    } catch (e) {
      setError({ msg: (e as Error).message, question: text });
    } finally {
      setBusy(false);
      inputRef.current?.focus();
    }
  };

  const submit = (e: FormEvent) => { e.preventDefault(); ask(q); };
  const onKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); ask(q); }
  };
  const s = job.summary;
  const provider = status.data?.ai.provider ?? "deterministic";

  return (
    <div className="grid gap-8 lg:grid-cols-[300px_minmax(0,1fr)] xl:grid-cols-[320px_minmax(0,1fr)]">
      <aside className="space-y-6 lg:sticky lg:top-[calc(var(--topbar-h)+112px)] lg:self-start">
        <Card title="Investigation context">
          <dl className="space-y-4 text-sm">
            <div><dt className="text-xs font-medium uppercase tracking-[0.06em] text-muted">Case</dt><dd className="mt-1 font-mono text-ink">{job.case_number}</dd></div>
            <div><dt className="text-xs font-medium uppercase tracking-[0.06em] text-muted">Memory image</dt><dd className="mt-1 break-all text-ink">{job.image.original_filename}</dd></div>
            <div className="flex gap-8">
              <div><dt className="text-xs font-medium uppercase tracking-[0.06em] text-muted">Findings</dt><dd className="mt-1 text-lg font-semibold tabular text-ink">{s.findings ?? 0}</dd></div>
              <div><dt className="text-xs font-medium uppercase tracking-[0.06em] text-muted">Risk</dt><dd className="mt-1.5"><RiskBadge score={job.overall_risk_score} band={job.overall_risk_band} /></dd></div>
            </div>
            <div><dt className="text-xs font-medium uppercase tracking-[0.06em] text-muted">AI engine</dt>
              <dd className="mt-1 inline-flex items-center gap-1.5 text-ink"><Cpu className="h-3.5 w-3.5 text-muted" />{provider}{status.data?.ai.model && <span className="text-muted"> · {status.data.ai.model}</span>}</dd></div>
          </dl>
        </Card>
        <Card title="Suggested questions">
          <div className="-mx-2 flex flex-col">
            {SUGGESTIONS.map((x) => (
              <button key={x} type="button" onClick={() => ask(x)} disabled={busy}
                className="group flex items-center gap-2 rounded-lg px-2 py-2 text-left text-[13px] text-ink-2 transition-colors hover:bg-surface-2 hover:text-ink disabled:opacity-50">
                <MessageSquareText className="h-3.5 w-3.5 shrink-0 text-faint" /><span className="flex-1">{x}</span>
                <ChevronRight className="h-3.5 w-3.5 text-faint opacity-0 transition-opacity group-hover:opacity-100" />
              </button>
            ))}
          </div>
        </Card>
        <details className="group rounded-2xl border border-line bg-surface p-5 shadow-card">
          <summary className="flex cursor-pointer list-none items-center gap-2 text-sm font-semibold text-ink [&::-webkit-details-marker]:hidden">
            <ShieldCheck className="h-4 w-4 text-good-text" />How answers are grounded
            <ChevronRight className="ml-auto h-4 w-4 text-muted transition-transform group-open:rotate-90" />
          </summary>
          <ol className="mt-4 space-y-3 text-[13px] leading-relaxed text-muted">
            <li><span className="font-medium text-ink-2">Evidence store</span> - stored artifacts become citable documents (F-, PROC-, NET-, MEM-, IOC-, TL-).</li>
            <li><span className="font-medium text-ink-2">Retriever</span> - intent, entity matching and BM25 select relevant evidence.</li>
            <li><span className="font-medium text-ink-2">Engine</span> - configured LLM or the deterministic engine composes the answer.</li>
            <li><span className="font-medium text-ink-2">Validator</span> - unknown citations, PIDs, IPs, hashes or binaries trigger regeneration, then an "uncertain" mark.</li>
          </ol>
        </details>
      </aside>

      <section className="flex min-w-0 flex-col">
        <div className="mb-8 flex items-start gap-4">
          <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br from-accent-strong to-cyan text-white shadow-raised"><Sparkles className="h-5 w-5" /></span>
          <div>
            <h1 className="text-[26px] font-semibold leading-tight tracking-[-0.02em] text-ink md:text-[30px]">Forensic AI</h1>
            <p className="mt-1 text-[15px] text-muted">Evidence-grounded analysis assistant for {job.case_number}</p>
          </div>
        </div>

        <div className="flex-1 space-y-8">
          {history.loading && !history.data && <Card><SkeletonAI /></Card>}
          {history.error && <ErrorState compact message={history.error} onRetry={history.reload} />}
          {!history.loading && messages.length === 0 && !busy && (
            <Card>
              <div className="px-2 py-6 text-center">
                <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-accent-soft text-accent-text"><Bot className="h-6 w-6" /></span>
                <h2 className="mt-5 text-lg font-semibold text-ink">Ask about this investigation</h2>
                <p className="mx-auto mt-2 max-w-lg text-sm leading-relaxed text-muted">
                  Answers are built from <span className="font-medium text-ink-2">retrieved evidence only</span>, cite evidence IDs you can open, and are checked by a response validator.
                  When evidence is missing the assistant says <i>"Insufficient evidence in the analyzed memory image."</i>
                </p>
                <div className="mx-auto mt-8 grid max-w-2xl gap-3 text-left sm:grid-cols-2">
                  {SUGGESTIONS.slice(0, 4).map((x) => (
                    <button key={x} type="button" onClick={() => ask(x)}
                      className="rounded-xl border border-line bg-surface-2/50 px-4 py-3.5 text-sm text-ink-2 transition-colors hover:border-accent/40 hover:bg-accent-soft hover:text-ink">{x}</button>
                  ))}
                </div>
              </div>
            </Card>
          )}
          {messages.map((m, idx) => m.role === "user" ? (
            <div key={m.id} className="flex justify-end">
              <div className="max-w-[85%] rounded-2xl rounded-br-md bg-accent-strong px-5 py-3.5 text-[15px] leading-relaxed text-white shadow-card">{m.content}</div>
            </div>
          ) : (
            <AIMessage key={m.id} defaultCollapsed={idx < messages.length - 1} content={m.content} citations={m.citations} validation={m.validation} provider={m.provider}
              onCite={(id) => cite(id, m.citations)}
              actions={<>
                {firstPid(m.citations) != null && <Button size="sm" icon={<Cpu />} to={`${base}/processes/${firstPid(m.citations)}`}>Open process</Button>}
                {m.citations.some((c) => c.kind === "finding") && <Button size="sm" icon={<ShieldAlert />} to={`${base}/findings`}>View evidence</Button>}
                <Button size="sm" variant="ghost" icon={<Database />} to={`${base}/reports`}>Reports</Button>
              </>} />
          ))}
          {busy && (
            <div className="rounded-2xl border border-line bg-surface p-6 shadow-card">
              <div className="mb-5 flex items-center gap-2.5 text-sm text-muted"><Sparkles className="h-4 w-4 animate-pulse text-accent-text" />Retrieving evidence and composing a grounded answer...</div>
              <SkeletonAI />
            </div>
          )}
          {error && <ErrorState compact message={error.msg} onRetry={() => ask(error.question)} />}
          <div ref={endRef} />
        </div>

        <form onSubmit={submit} className="sticky bottom-0 z-[2] -mx-1 mt-8 bg-gradient-to-t from-page from-70% to-transparent px-1 pb-5 pt-6">
          <div className={cx("flex items-end gap-3 rounded-2xl border bg-surface p-2.5 pl-4 shadow-raised transition-[border-color,box-shadow]",
            "border-line focus-within:border-accent focus-within:ring-4 focus-within:ring-accent/15")}>
            <textarea ref={inputRef} rows={1} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey} maxLength={2000}
              placeholder="Ask about processes, PIDs, injection, network activity..." aria-label="Question"
              className="max-h-[180px] min-h-[40px] flex-1 resize-none bg-transparent py-2 text-[15px] leading-relaxed text-ink placeholder:text-faint focus:outline-none" />
            <Button type="submit" variant="primary" disabled={busy || !q.trim()} aria-label="Send question" className="h-10 w-10 !px-0"><ArrowUp /></Button>
          </div>
          <p className="mt-2 px-1 text-xs text-faint">Enter to send · Shift + Enter for a new line · answers cite evidence from this analysis only</p>
        </form>
      </section>
    </div>
  );
}
