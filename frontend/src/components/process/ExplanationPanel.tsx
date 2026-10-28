import { Bot, ExternalLink, RefreshCw, ShieldCheck, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { useApi } from "../../hooks/useApi";
import { api } from "../../services/api";
import { CATEGORY_LABEL } from "../../services/format";
import type { Finding } from "../../types";
import { EvidenceList } from "../forensic/cards";
import { Badge, Button, ConfidenceMeter, ErrorState, SeverityBadge, SkeletonAI } from "../ui";

function Section({ n, title, children, tone }: { n: number; title: string; children: ReactNode; tone?: "warn" }) {
  return (
    <section className={tone === "warn" ? "rounded-xl border border-sev-medium/25 bg-sev-medium/[0.06] p-5" : ""}>
      <h4 className="mb-2.5 flex items-center gap-2.5 text-[13px] font-semibold uppercase tracking-[0.06em] text-muted">
        <span className="font-mono text-[11px] text-faint">{String(n).padStart(2, "0")}</span>{title}
      </h4>
      <div className="text-[14.5px] leading-relaxed text-ink-2">{children}</div>
    </section>
  );
}

/** Explainable-AI view of a single finding. Evidence and confidence are always taken from stored data. */
export function ExplanationPanel({ finding }: { finding: Finding }) {
  const { data, error, loading, reload, setData } = useApi(() => api.explanation(finding.id), [finding.id]);
  const regenerate = async () => setData(await api.explanation(finding.id, true));

  return (
    <div className="space-y-7">
      <div>
        <div className="flex flex-wrap items-center gap-2.5">
          <SeverityBadge severity={finding.severity} size="md" />
          <Badge>{CATEGORY_LABEL[finding.category] ?? finding.category}</Badge>
          <span className="font-mono text-xs text-muted">{finding.rule_id}</span>
          {finding.attack_techniques.map((t) => (
            <a key={t} href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`} target="_blank" rel="noreferrer"
              className="inline-flex items-center gap-1 rounded-md border border-line px-1.5 py-0.5 font-mono text-[11px] text-ink-2 hover:border-accent/40 hover:text-accent-text">
              {t}<ExternalLink className="h-3 w-3" />
            </a>
          ))}
        </div>
        <p className="mt-4 text-[15px] leading-relaxed text-ink">{finding.finding}</p>
        <div className="mt-4 flex flex-wrap items-center gap-x-6 gap-y-2 text-[13px] text-muted">
          <span className="inline-flex items-center gap-2">Confidence <ConfidenceMeter value={finding.confidence} /></span>
          <span>Score contribution <span className="font-semibold tabular text-ink">+{finding.points}</span></span>
        </div>
      </div>

      {loading && !data ? <SkeletonAI /> : error ? <ErrorState compact message={error} onRetry={reload} /> : data && (
        <>
          <div className="flex flex-wrap items-center gap-2.5 rounded-xl bg-surface-2/70 px-4 py-3 text-[13px] text-muted">
            <Bot className="h-4 w-4 text-accent-text" />
            Explained by <span className="font-medium text-ink-2">{data.provider}</span>{data.model && ` (${data.model})`}
            {data.grounded ? <Badge tone="success" icon={<ShieldCheck />}>Validated against evidence</Badge>
              : <Badge tone="warning" icon={<TriangleAlert />}>Contains unverified statements</Badge>}
            <Button size="sm" variant="ghost" onClick={regenerate} icon={<RefreshCw />} className="ml-auto">Regenerate</Button>
          </div>
          {(data.validation.warnings ?? []).length > 0 && <p className="text-[13px] text-sev-medium-text">{data.validation.warnings!.join(" ")}</p>}
          <Section n={1} title="What happened">{data.content.what_happened}</Section>
          <Section n={2} title="Why it is suspicious">{data.content.why_suspicious}</Section>
          <Section n={3} title="Evidence (forensic artifacts)"><EvidenceList items={data.content.evidence} /></Section>
          <Section n={4} title="Confidence">
            <span className="font-semibold text-ink">{data.content.confidence.level}</span> <span className="tabular text-muted">({data.content.confidence.value})</span>
            <span className="mt-1 block text-[13px] text-muted">{data.content.confidence.basis}</span>
          </Section>
          <Section n={5} title="Possible interpretation">{data.content.possible_interpretation}</Section>
          <Section n={6} title="What it does not prove" tone="warn">{data.content.does_not_prove}</Section>
          <Section n={7} title="Recommended next investigation">{data.content.recommended_next_steps}</Section>
        </>
      )}
    </div>
  );
}
