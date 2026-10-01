import { Trash2, Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Page } from "../components/layout/AppLayout";
import { Button, Card, ConfirmDialog, ErrorState, Field, inputCls, Loading, Notice, PageHeader, SeverityBadge, Tabs } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { api } from "../services/api";
import type { AISettings, YaraRuleFile } from "../types";

export default function SettingsPage() {
  const [tab, setTab] = useState<"ai" | "rules" | "yara" | "scoring">("ai");
  return (
    <Page>
      <PageHeader title="Settings" subtitle="AI provider, detection rules, YARA rules and the risk-scoring model." />
      <Tabs value={tab} onChange={setTab} tabs={[{ key: "ai", label: "AI provider" }, { key: "rules", label: "Detection rules" }, { key: "yara", label: "YARA rules" }, { key: "scoring", label: "Scoring model" }]} />
      {tab === "ai" && <AiSettings />}
      {tab === "rules" && <RuleSettings />}
      {tab === "yara" && <YaraSettings />}
      {tab === "scoring" && <ScoringSettings />}
    </Page>
  );
}

function AiSettings() {
  const { user } = useAuth();
  const { data, error, loading } = useApi(() => api.aiSettings(), []);
  const [form, setForm] = useState<AISettings | null>(null);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  useEffect(() => { if (data) setForm(data); }, [data]);
  if (loading || !form) return error ? <ErrorState message={error} /> : <Loading />;
  const admin = user?.role === "admin";

  const save = async () => {
    try {
      setForm(await api.saveAiSettings({ provider: form.provider, base_url: form.base_url, model: form.model, temperature: form.temperature }));
      setMsg({ tone: "ok", text: "Saved." });
    } catch (e) { setMsg({ tone: "danger", text: (e as Error).message }); }
  };
  const test = async () => {
    const r = await api.testAi().catch((e: Error) => ({ ok: false, detail: e.message }));
    setMsg({ tone: r.ok ? "ok" : "danger", text: `${r.ok ? "Provider reachable" : "Provider test failed"}: ${r.detail}` });
  };

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="LLM provider">
        <div className="space-y-4">
          <Field label="Provider" hint="Deterministic needs no external service and cannot hallucinate. LLM output is always validated against the evidence store.">
            <select className={inputCls} value={form.provider} disabled={!admin} onChange={(e) => setForm({ ...form, provider: e.target.value as AISettings["provider"] })}>
              <option value="deterministic">Deterministic explanation engine (offline)</option>
              <option value="openai">OpenAI-compatible API (OpenAI, vLLM, LM Studio, llama.cpp, OpenRouter...)</option>
              <option value="ollama">Ollama (local)</option>
            </select>
          </Field>
          {form.provider !== "deterministic" && (<>
            <Field label="Base URL" hint={form.provider === "ollama" ? "e.g. http://localhost:11434" : "e.g. https://api.openai.com/v1 or http://localhost:1234/v1"}>
              <input className={inputCls} value={form.base_url} disabled={!admin} onChange={(e) => setForm({ ...form, base_url: e.target.value })} />
            </Field>
            <Field label="Model"><input className={inputCls} value={form.model} disabled={!admin} onChange={(e) => setForm({ ...form, model: e.target.value })} /></Field>
            <Field label={`Temperature (${form.temperature})`}>
              <input type="range" min={0} max={1} step={0.05} value={form.temperature} disabled={!admin} onChange={(e) => setForm({ ...form, temperature: Number(e.target.value) })} className="w-full accent-[#3987e5]" />
            </Field>
            <Notice tone={form.api_key_configured ? "ok" : "warn"}>API key {form.api_key_configured ? "is configured" : "is not configured"} via the <code>AI_API_KEY</code> environment variable. Keys are never stored in the database or shown in the UI.</Notice>
          </>)}
          {msg && <Notice tone={msg.tone}>{msg.text}</Notice>}
          <div className="flex gap-2">
            <Button variant="primary" onClick={save} disabled={!admin}>Save</Button>
            <Button onClick={test} disabled={!admin}>Test connection</Button>
          </div>
          {!admin && <p className="text-xs text-muted">Only administrators can change the AI provider.</p>}
        </div>
      </Card>
      <Card title="Privacy & grounding">
        <ul className="list-disc space-y-2 pl-4 text-sm text-ink-2">
          <li>The LLM never receives the memory image - only retrieved, structured evidence summaries.</li>
          <li>When an external API is used, evidence summaries (process names, paths, IPs) leave this server. Use Ollama or the deterministic engine for sensitive cases.</li>
          <li>Every answer is validated: unknown citations, PIDs, IPs, hashes or binaries cause regeneration, then an "uncertain" mark.</li>
          <li>If the provider fails, the deterministic engine answers instead.</li>
        </ul>
      </Card>
    </div>
  );
}

function RuleSettings() {
  const { user } = useAuth();
  const { data, error, loading, setData } = useApi(() => api.rules(), []);
  if (loading && !data) return <Loading />;
  if (error) return <ErrorState message={error} />;
  const toggle = async (id: string, enabled: boolean) => {
    const r = await api.toggleRule(id, enabled);
    setData((data ?? []).map((x) => (x.rule_id === id ? r : x)));
  };
  return (
    <Card title="Detection rules" actions={<span className="text-xs text-muted">Baselines and patterns are configured in rules/*.yaml</span>}>
      <div className="divide-y divide-line">
        {(data ?? []).map((r) => (
          <div key={r.rule_id} className="flex flex-wrap items-start gap-3 py-3">
            <label className="mt-0.5 flex items-center"><input type="checkbox" className="accent-[#3987e5]" checked={r.enabled} disabled={user?.role !== "admin"} onChange={(e) => toggle(r.rule_id, e.target.checked)} aria-label={`Enable ${r.rule_id}`} /></label>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-sm text-ink">{r.rule_id}</span><SeverityBadge severity={r.default_severity} />
                <span className="text-xs text-muted">{r.category} - {r.base_points} pts</span>{r.attack_techniques.map((t) => <span key={t} className="rounded bg-surface-3 px-1 font-mono text-[10px]">{t}</span>)}</div>
              <div className="text-sm text-ink-2">{r.title}</div>
              <div className="text-xs text-muted">{r.description}</div>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function YaraSettings() {
  const { user } = useAuth();
  const { data, error, loading, reload } = useApi(() => api.yaraRules(), []);
  const ref = useRef<HTMLInputElement>(null);
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [del, setDel] = useState<YaraRuleFile | null>(null);
  const upload = async (f?: File) => {
    if (!f) return;
    try {
      const r = await api.uploadYara(f);
      setMsg({ tone: "ok", text: `Uploaded ${r.filename}: ${r.rule_names.length} rule(s).` });
      reload();
    } catch (e) { setMsg({ tone: "danger", text: (e as Error).message }); }
    if (ref.current) ref.current.value = "";
  };
  return (
    <Card title="YARA rule files" actions={<><input ref={ref} type="file" accept=".yar,.yara" className="hidden" onChange={(e) => upload(e.target.files?.[0])} />
      <Button onClick={() => ref.current?.click()}><Upload className="h-4 w-4" />Upload rules</Button></>}>
      <div className="mb-3"><Notice>Enabled rules are bundled and scanned with <code>windows.vadyarascan</code> on triaged processes. <code>include</code> directives are rejected. A YARA match is an indicator, not proof.</Notice></div>
      {msg && <div className="mb-3"><Notice tone={msg.tone}>{msg.text}</Notice></div>}
      {loading && !data ? <Loading /> : error ? <ErrorState message={error} /> : (
        <div className="divide-y divide-line">
          {(data ?? []).map((y) => (
            <div key={y.id} className="flex flex-wrap items-center gap-3 py-3">
              <input type="checkbox" className="accent-[#3987e5]" checked={y.enabled} aria-label={`Enable ${y.filename}`}
                onChange={async (e) => { await api.toggleYara(y.id, e.target.checked); reload(); }} />
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium text-ink">{y.filename} {y.builtin && <span className="ml-1 rounded bg-surface-3 px-1 text-[10px] text-muted">built-in</span>}</div>
                <div className="text-xs text-muted">{y.rule_names.join(", ")}</div>
              </div>
              {!y.builtin && user?.role === "admin" && <Button variant="ghost" onClick={() => setDel(y)}><Trash2 className="h-4 w-4" /></Button>}
            </div>
          ))}
        </div>
      )}
      <ConfirmDialog open={!!del} danger title="Delete YARA rule file?" confirmLabel="Delete" onCancel={() => setDel(null)}
        onConfirm={async () => { if (del) await api.deleteYara(del.id); setDel(null); reload(); }}>
        {del?.filename} will be removed. Past analyses keep their recorded matches.
      </ConfirmDialog>
    </Card>
  );
}

function ScoringSettings() {
  const { data, error, loading } = useApi(() => api.scoringModel(), []);
  if (loading && !data) return <Loading />;
  if (error || !data) return <ErrorState message={error ?? "Unavailable"} />;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Formula">
        <p className="text-sm text-ink-2">{data.formula}</p>
        <div className="mt-4 grid grid-cols-2 gap-2 text-sm">{data.bands.map((b) => <div key={b.name} className="rounded-lg border border-line px-3 py-2 capitalize">{b.name}: <span className="tabular">{b.min}-{b.max}</span></div>)}</div>
        <div className="mt-4"><Notice tone="warn">{data.disclaimer}</Notice></div>
      </Card>
      <Card title="Category caps (rules/scoring.yaml)">
        <table className="w-full text-sm"><tbody className="divide-y divide-line">
          {Object.entries(data.category_caps).map(([k, v]) => <tr key={k}><td className="py-1.5 text-ink-2">{k.replace(/_/g, " ")}</td><td className="text-right tabular text-ink">{v}</td></tr>)}
          <tr><td className="py-1.5 text-ink-2">corroboration bonus (&ge;{data.corroboration.min_categories} categories)</td><td className="text-right tabular text-ink">+{data.corroboration.bonus}</td></tr>
        </tbody></table>
      </Card>
    </div>
  );
}
