import { Bot, Send, ShieldCheck, TriangleAlert, User } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAnalysis } from "../components/layout/AppLayout";
import { Button, Card, cx, ErrorState, inputCls, Loading, Markdown } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { ChatMessage, Citation, Validation } from "../types";

const SUGGESTIONS = [
  "Which processes are most suspicious?",
  "Why is PID 4528 suspicious?",
  "What evidence suggests process injection?",
  "Show me suspicious parent-child relationships.",
  "What network connections belong to suspicious processes?",
  "Summarize the investigation.",
  "Explain this finding in simple language.",
  "Generate an incident timeline.",
  "What additional evidence should an investigator examine?",
];

function ValidationBadge({ v }: { v: Partial<Validation> }) {
  if (!v.status) return null;
  const ok = v.status === "grounded";
  return (
    <span className={cx("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium",
      ok ? "bg-good/15 text-good" : "bg-sev-medium/15 text-sev-medium")}
      title={[...(v.warnings ?? []), ...(v.unsupported_entities ?? []).map((e) => `unsupported: ${e}`), ...(v.overclaims ?? []).map((o) => `over-claim: ${o}`)].join("\n")}>
      {ok ? <ShieldCheck className="h-3 w-3" /> : <TriangleAlert className="h-3 w-3" />}
      {ok ? "Grounded in evidence" : `Validator: ${v.status}`}
    </span>
  );
}

export default function AssistantPage() {
  const { job, jobId } = useAnalysis();
  const nav = useNavigate();
  const history = useApi(() => api.aiHistory(jobId), [jobId]);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => { if (history.data) setMessages(history.data); }, [history.data]);
  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
  }, [messages, busy]);

  const ask = async (question: string) => {
    if (!question.trim() || busy) return;
    setBusy(true);
    setError(null);
    setQ("");
    const now = new Date().toISOString();
    setMessages((m) => [...m, { id: -Date.now(), role: "user", content: question, citations: [], validation: {}, provider: null, created_at: now }]);
    try {
      const a = await api.aiQuery(jobId, question);
      setMessages((m) => [...m, { id: a.message_id ?? -Date.now() - 1, role: "assistant", content: a.answer, citations: a.citations,
        validation: a.validation, provider: a.provider, created_at: new Date().toISOString() }]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const onCite = (id: string, citations: Citation[]) => {
    const c = citations.find((x) => x.id === id);
    const pid = c?.pid ?? (/^PROC-(\d+)/.exec(id)?.[1] ? Number(/^PROC-(\d+)/.exec(id)![1]) : null);
    if (id.startsWith("F-")) nav(`/analysis/${jobId}/findings`);
    else if (id.startsWith("NET-")) nav(`/analysis/${jobId}/network`);
    else if (id.startsWith("MEM-")) nav(`/analysis/${jobId}/memory`);
    else if (id.startsWith("IOC-")) nav(`/analysis/${jobId}/iocs`);
    else if (id.startsWith("TL-")) nav(`/analysis/${jobId}/timeline`);
    else if (pid != null) nav(`/analysis/${jobId}/processes/${pid}`);
  };

  const submit = (e: FormEvent) => { e.preventDefault(); ask(q); };

  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_300px]">
      <Card pad={false} title={<span className="flex items-center gap-2"><Bot className="h-4 w-4 text-accent" />Forensic AI assistant - {job.case_number}</span>}>
        <div className="flex h-[68vh] flex-col">
          <div ref={scrollRef} className="flex-1 space-y-4 overflow-y-auto p-4">
            {history.loading && !history.data && <Loading />}
            {messages.length === 0 && !history.loading && (
              <div className="mx-auto max-w-lg py-10 text-center text-sm text-muted">
                Ask about this investigation. Answers are built from <b className="text-ink-2">retrieved evidence only</b>,
                cite evidence IDs (click them to navigate) and are checked by a response validator. When evidence is missing the assistant
                says <i>"Insufficient evidence in the analyzed memory image."</i>
              </div>
            )}
            {messages.map((m) => (
              <div key={m.id} className={cx("flex gap-3", m.role === "user" && "flex-row-reverse")}>
                <div className={cx("mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-full", m.role === "user" ? "bg-surface-3" : "bg-accent/20")}>
                  {m.role === "user" ? <User className="h-4 w-4 text-ink-2" /> : <Bot className="h-4 w-4 text-accent" />}
                </div>
                <div className={cx("min-w-0 max-w-[85%] rounded-xl px-4 py-3", m.role === "user" ? "bg-accent-strong/30 text-ink" : "border border-line bg-surface-2")}>
                  {m.role === "user" ? <p className="text-sm">{m.content}</p> : (
                    <>
                      <Markdown text={m.content} onCite={(id) => onCite(id, m.citations)} />
                      <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line pt-2 text-[11px] text-muted">
                        <ValidationBadge v={m.validation} />
                        <span>{m.citations.length} evidence item(s) cited</span>
                        {m.provider && <span>- engine: {m.provider}</span>}
                      </div>
                    </>
                  )}
                </div>
              </div>
            ))}
            {busy && <Loading label="Retrieving evidence and composing a grounded answer..." />}
            {error && <ErrorState message={error} />}
          </div>
          <form onSubmit={submit} className="flex gap-2 border-t border-line p-3">
            <input className={inputCls} value={q} onChange={(e) => setQ(e.target.value)} placeholder="e.g. Why is PID 4528 suspicious?" maxLength={2000} aria-label="Question" />
            <Button type="submit" variant="primary" disabled={busy || !q.trim()}><Send className="h-4 w-4" />Ask</Button>
          </form>
        </div>
      </Card>
      <div className="space-y-4">
        <Card title="Suggested questions">
          <div className="flex flex-col gap-1.5">
            {SUGGESTIONS.map((s) => (
              <button key={s} onClick={() => ask(s)} disabled={busy} className="rounded-lg border border-line px-3 py-2 text-left text-sm text-ink-2 hover:border-accent/50 hover:bg-surface-2 disabled:opacity-50">{s}</button>
            ))}
          </div>
        </Card>
        <Card title="How answers are produced">
          <ol className="list-decimal space-y-1 pl-4 text-xs text-muted">
            <li>Evidence store: stored artifacts become citable documents (F-, PROC-, NET-, MEM-, IOC-, TL-).</li>
            <li>Retriever: intent + entity matching + BM25 selects relevant evidence.</li>
            <li>Prompt builder / LLM (if configured) or deterministic engine.</li>
            <li>Validator: rejects unknown citations, PIDs, IPs, hashes and binaries not in evidence; flags over-claiming.</li>
          </ol>
        </Card>
      </div>
    </div>
  );
}
