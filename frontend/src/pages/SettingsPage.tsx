import { Bot, Calculator, FileCode2, ListChecks, Lock, PlugZap, ScanLine, Trash2, Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Page } from "../components/layout/AppLayout";
import { useCrumbs } from "../components/layout/crumbs";
import {
  Badge, Button, Card, ConfirmDialog, DataTable, EmptyState, ErrorState, Field, inputCls, Notice, PageHeader, Select, SeverityBadge, Skeleton,
  SkeletonTable, Switch, Tabs,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../hooks/useAuth";
import { useToast } from "../hooks/useToast";
import { api } from "../services/api";
import { CATEGORY_LABEL, fmtTime } from "../services/format";
import type { AISettings, Rule, YaraRuleFile } from "../types";

type Tab = "ai" | "rules" | "yara" | "scoring";

export default function SettingsPage() {
  useCrumbs([{ label: "Administration" }, { label: "Settings" }]);
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as Tab) ?? "ai";
  const { user } = useAuth();
  return (
    <Page>
      <PageHeader title="Settings" subtitle="AI provider, detection rules, YARA rule files and the risk-scoring model."
        meta={user?.role !== "admin" && <span className="inline-flex items-center gap-1.5"><Lock className="h-3.5 w-3.5" />Read-only: only administrators can change settings</span>} />
      <Tabs value={tab} onChange={(t) => setParams(t === "ai" ? {} : { tab: t }, { replace: true })} tabs={[
        { key: "ai", label: "AI provider", icon: <Bot /> }, { key: "rules", label: "Detection rules", icon: <ListChecks /> },
        { key: "yara", label: "YARA rules", icon: <ScanLine /> }, { key: "scoring", label: "Scoring model", icon: <Calculator /> },
      ]} />
      <div key={tab} className="animate-page-in">
        {tab === "ai" && <AiSettings />}
        {tab === "rules" && <RuleSettings />}
        {tab === "yara" && <YaraSettings />}
        {tab === "scoring" && <ScoringSettings />}
      </div>
    </Page>
  );
}

function AiSettings() {
  const { user } = useAuth();
  const toast = useToast();
  const { data, error, loading, reload } = useApi(() => api.aiSettings(), []);
  const [form, setForm] = useState<AISettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  useEffect(() => { if (data) setForm(data); }, [data]);
  if (error) return <ErrorState title="AI settings unavailable" message={error} onRetry={reload} />;
  if (loading || !form) return <Card><div className="space-y-6"><Skeleton className="h-10" /><Skeleton className="h-10" /><Skeleton className="h-10 w-1/2" /></div></Card>;
  const admin = user?.role === "admin";

  const save = async () => {
    setSaving(true);
    try {
      setForm(await api.saveAiSettings({ provider: form.provider, base_url: form.base_url, model: form.model, temperature: form.temperature }));
      toast({ tone: "success", title: "AI provider saved" });
    } catch (e) {
      toast({ tone: "error", title: "Could not save", description: (e as Error).message });
    } finally {
      setSaving(false);
    }
  };
  const test = async () => {
    setTesting(true);
    const r = await api.testAi().catch((e: Error) => ({ ok: false, detail: e.message }));
    setTesting(false);
    toast({ tone: r.ok ? "success" : "error", title: r.ok ? "Provider reachable" : "Provider test failed", description: r.detail });
  };

  return (
    <div className="grid gap-6 lg:grid-cols-12">
      <Card className="lg:col-span-7" title="LLM provider" subtitle="LLM output is always validated against the evidence store; the deterministic engine is the fallback.">
        <div className="space-y-6">
          <Field label="Provider" hint="The deterministic engine needs no external service and cannot hallucinate.">
            <Select label="Provider" value={form.provider} onChange={(v) => setForm({ ...form, provider: v as AISettings["provider"] })} className="w-full">
              <option value="deterministic">Deterministic explanation engine (offline)</option>
              <option value="openai">OpenAI-compatible API (OpenAI, vLLM, LM Studio, llama.cpp, OpenRouter...)</option>
              <option value="ollama">Ollama (local)</option>
            </Select>
          </Field>
          {form.provider !== "deterministic" && (
            <>
              <Field label="Base URL" hint={form.provider === "ollama" ? "e.g. http://localhost:11434" : "e.g. https://api.openai.com/v1 or http://localhost:1234/v1"}>
                <input className={inputCls} value={form.base_url} disabled={!admin} onChange={(e) => setForm({ ...form, base_url: e.target.value })} />
              </Field>
              <Field label="Model"><input className={inputCls} value={form.model} disabled={!admin} onChange={(e) => setForm({ ...form, model: e.target.value })} /></Field>
              <Field label={`Temperature · ${form.temperature}`} hint="Lower is more deterministic. 0.1 is recommended for forensic explanations.">
                <input type="range" min={0} max={1} step={0.05} value={form.temperature} disabled={!admin}
                  onChange={(e) => setForm({ ...form, temperature: Number(e.target.value) })} className="w-full accent-[var(--color-accent)]" />
              </Field>
              <Notice tone={form.api_key_configured ? "ok" : "warn"}>API key {form.api_key_configured ? "is configured" : "is not configured"} via the <code className="font-mono text-[13px]">AI_API_KEY</code> environment variable. Keys are never stored in the database or shown in the UI.</Notice>
            </>
          )}
          <div className="flex flex-wrap gap-2.5 border-t border-line pt-6">
            <Button variant="primary" onClick={save} disabled={!admin || saving}>{saving ? "Saving..." : "Save changes"}</Button>
            <Button onClick={test} disabled={!admin || testing} icon={<PlugZap />}>{testing ? "Testing..." : "Test connection"}</Button>
          </div>
        </div>
      </Card>
      <Card className="lg:col-span-5 lg:self-start" title="Privacy & grounding">
        <ul className="space-y-4 text-sm leading-relaxed text-ink-2">
          <li>The LLM never receives the memory image - only retrieved, structured evidence summaries.</li>
          <li>With an external API, evidence summaries (process names, paths, IPs) leave this server. Use Ollama or the deterministic engine for sensitive cases.</li>
          <li>Unknown citations, PIDs, IPs, hashes or binaries cause regeneration, then an "uncertain" mark.</li>
          <li>If the provider fails, the deterministic engine answers instead.</li>
        </ul>
      </Card>
    </div>
  );
}

function RuleSettings() {
  const { user } = useAuth();
  const toast = useToast();
  const { data, error, loading, setData, reload } = useApi(() => api.rules(), []);
  const admin = user?.role === "admin";
  const toggle = async (r: Rule, enabled: boolean) => {
    try {
      const out = await api.toggleRule(r.rule_id, enabled);
      setData((data ?? []).map((x) => (x.rule_id === r.rule_id ? out : x)));
      toast({ tone: "success", title: `${r.rule_id} ${enabled ? "enabled" : "disabled"}` });
    } catch (e) {
      toast({ tone: "error", title: "Rule not updated", description: (e as Error).message });
    }
  };
  if (error) return <ErrorState title="Rules unavailable" message={error} onRetry={reload} />;
  return (
    <Card pad={false} title="Detection rules" subtitle="Baselines and patterns are configured in rules/*.yaml. Disabled rules are reported as not evaluated.">
      {loading && !data ? <SkeletonTable /> : (
        <DataTable<Rule> rows={data ?? []} rowKey={(r) => r.rule_id} pageSize={30} searchPlaceholder="Search rules..."
          columns={[
            { key: "enabled", header: "On", sortValue: (r) => Number(r.enabled), render: (r) => (
              <Switch checked={r.enabled} disabled={!admin} onChange={(v) => toggle(r, v)} label={<span className="sr-only">Enable {r.rule_id}</span>} />) },
            { key: "title", header: "Rule", render: (r) => (
              <div className="min-w-[260px] max-w-xl py-0.5">
                <div className="font-medium text-ink">{r.title}</div>
                <div className="mt-0.5 font-mono text-xs text-muted">{r.rule_id}</div>
                <div className="mt-1.5 text-[13px] leading-relaxed text-muted">{r.description}</div>
              </div>) },
            { key: "category", header: "Category", render: (r) => <span className="whitespace-nowrap text-[13px]">{CATEGORY_LABEL[r.category] ?? r.category}</span> },
            { key: "default_severity", header: "Severity", render: (r) => <SeverityBadge severity={r.default_severity} /> },
            { key: "base_points", header: "Points", align: "right", className: "tabular" },
            { key: "attack", header: "ATT&CK", sortable: false, render: (r) => <span className="flex flex-wrap gap-1">{r.attack_techniques.map((t) => <Badge key={t} className="font-mono font-medium">{t}</Badge>)}</span> },
          ]} />
      )}
    </Card>
  );
}

function YaraSettings() {
  const { user } = useAuth();
  const toast = useToast();
  const { data, error, loading, reload } = useApi(() => api.yaraRules(), []);
  const ref = useRef<HTMLInputElement>(null);
  const [del, setDel] = useState<YaraRuleFile | null>(null);
  const admin = user?.role === "admin";
  const upload = async (f?: File) => {
    if (!f) return;
    try {
      const r = await api.uploadYara(f);
      toast({ tone: "success", title: `Uploaded ${r.filename}`, description: `${r.rule_names.length} rule(s) compiled and validated.` });
      reload();
    } catch (e) {
      toast({ tone: "error", title: "YARA upload rejected", description: (e as Error).message });
    }
    if (ref.current) ref.current.value = "";
  };
  if (error) return <ErrorState title="YARA rules unavailable" message={error} onRetry={reload} />;
  return (
    <div className="space-y-6">
      <Notice>Enabled rules are bundled and scanned with <code className="font-mono text-[13px]">windows.vadyarascan</code> on triaged processes. <code className="font-mono text-[13px]">include</code> directives are rejected. A YARA match is an indicator, not proof.</Notice>
      <Card pad={false} title="YARA rule files" actions={<>
        <input ref={ref} type="file" accept=".yar,.yara" className="hidden" onChange={(e) => upload(e.target.files?.[0])} />
        <Button onClick={() => ref.current?.click()} icon={<Upload />}>Upload rules</Button>
      </>}>
        {loading && !data ? <SkeletonTable rows={3} /> : !(data ?? []).length ? (
          <EmptyState title="No YARA rule files" icon={<FileCode2 />}>Upload a .yar file to scan triaged process memory.</EmptyState>
        ) : (
          <DataTable<YaraRuleFile> rows={data ?? []} rowKey={(y) => y.id} search={false}
            columns={[
              { key: "enabled", header: "On", sortValue: (y) => Number(y.enabled), render: (y) => (
                <Switch checked={y.enabled} onChange={async (v) => { await api.toggleYara(y.id, v); reload(); }} label={<span className="sr-only">Enable {y.filename}</span>} />) },
              { key: "filename", header: "File", render: (y) => (
                <div><div className="flex items-center gap-2 font-medium text-ink">{y.filename}{y.builtin && <Badge>Built-in</Badge>}</div>
                  <div className="mt-1 max-w-xl text-[13px] text-muted">{y.rule_names.join(", ")}</div></div>) },
              { key: "rules", header: "Rules", align: "right", sortValue: (y) => y.rule_names.length, render: (y) => <span className="tabular">{y.rule_names.length}</span> },
              { key: "uploaded_at", header: "Added (UTC)", render: (y) => <span className="whitespace-nowrap text-[13px] text-muted">{fmtTime(y.uploaded_at)}</span> },
              { key: "actions", header: "", sortable: false, align: "right", render: (y) => !y.builtin && admin
                ? <Button size="sm" variant="ghost" aria-label={`Delete ${y.filename}`} onClick={() => setDel(y)}><Trash2 /></Button> : null },
            ]} />
        )}
      </Card>
      <ConfirmDialog open={!!del} danger title="Delete YARA rule file?" confirmLabel="Delete" onCancel={() => setDel(null)}
        onConfirm={async () => { if (del) { await api.deleteYara(del.id); toast({ tone: "success", title: `${del.filename} deleted` }); } setDel(null); reload(); }}>
        {del?.filename} will be removed. Past analyses keep their recorded matches.
      </ConfirmDialog>
    </div>
  );
}

function ScoringSettings() {
  const { data, error, loading, reload } = useApi(() => api.scoringModel(), []);
  if (loading && !data) return <Card><Skeleton className="h-40" /></Card>;
  if (error || !data) return <ErrorState title="Scoring model unavailable" message={error ?? "Unavailable"} onRetry={reload} />;
  const bandColor: Record<string, string> = { critical: "var(--color-sev-critical)", high: "var(--color-sev-high)", moderate: "var(--color-sev-medium)", low: "var(--color-sev-low)" };
  return (
    <div className="grid gap-6 lg:grid-cols-12">
      <Card className="lg:col-span-7" title="Formula" subtitle="Explainable, additive and capped">
        <p className="rounded-xl border border-line bg-surface-2/60 p-5 font-mono text-[13px] leading-relaxed text-ink">{data.formula}</p>
        <div className="mt-8 text-[13px] font-semibold text-ink">Risk bands</div>
        <div className="mt-3 flex h-3 overflow-hidden rounded-full">
          {data.bands.slice().sort((a, b) => a.min - b.min).map((b) => (
            <span key={b.name} style={{ width: `${b.max - b.min + 1}%`, background: bandColor[b.name] ?? "var(--color-line-strong)" }} title={`${b.name}: ${b.min}-${b.max}`} />
          ))}
        </div>
        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          {data.bands.slice().sort((a, b) => a.min - b.min).map((b) => (
            <div key={b.name} className="rounded-xl border border-line px-4 py-3">
              <div className="flex items-center gap-2 text-sm font-medium capitalize text-ink"><span className="h-2 w-2 rounded-full" style={{ background: bandColor[b.name] }} />{b.name}</div>
              <div className="mt-1 text-[13px] tabular text-muted">{b.min} – {b.max}</div>
            </div>
          ))}
        </div>
        <Notice tone="warn" className="mt-8">{data.disclaimer}</Notice>
      </Card>
      <Card className="lg:col-span-5 lg:self-start" title="Category caps" subtitle="rules/scoring.yaml">
        <ul className="divide-y divide-line">
          {Object.entries(data.category_caps).map(([k, v]) => (
            <li key={k} className="flex items-center justify-between py-3 text-sm first:pt-0"><span className="text-ink-2">{CATEGORY_LABEL[k] ?? k.replace(/_/g, " ")}</span><span className="font-semibold tabular text-ink">{v}</span></li>
          ))}
          <li className="flex items-center justify-between gap-4 pt-3 text-sm"><span className="text-ink-2">Corroboration bonus (≥ {data.corroboration.min_categories} categories)</span><span className="font-semibold tabular text-good-text">+{data.corroboration.bonus}</span></li>
        </ul>
      </Card>
    </div>
  );
}
