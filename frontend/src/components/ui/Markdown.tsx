import type { ReactNode } from "react";

/* Safe Markdown subset rendered as React elements (no innerHTML): headings, paragraphs, lists, quotes, rules,
 * **bold**, `code` and evidence citations like [F-12] / [PROC-4528] which become clickable chips. */

const CITE = /(\*\*[^*]+\*\*|`[^`]+`|\[(?:F|PROC|NET|MEM|MOD|IOC|YARA|TL)-[\w.]+\]|\[SUMMARY\])/g;

function inline(text: string, onCite?: (id: string) => void): ReactNode[] {
  const parts: ReactNode[] = [];
  let last = 0;
  let k = 0;
  let m: RegExpExecArray | null;
  CITE.lastIndex = 0;
  while ((m = CITE.exec(text))) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("**")) parts.push(<strong key={k++}>{tok.slice(2, -2)}</strong>);
    else if (tok.startsWith("`")) parts.push(<code key={k++}>{tok.slice(1, -1)}</code>);
    else {
      const id = tok.slice(1, -1);
      parts.push(
        <button key={k++} type="button" onClick={() => onCite?.(id)} title={`Open evidence ${id}`}
          className="mx-0.5 inline-flex translate-y-[-1px] items-center rounded-md border border-accent/25 bg-accent-soft px-1.5 py-px align-middle font-mono text-[11px] font-medium text-accent-text transition-colors hover:border-accent/50 hover:bg-accent/15">
          {id}
        </button>,
      );
    }
    last = m.index + tok.length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}

export function Markdown({ text, onCite, className }: { text: string; onCite?: (id: string) => void; className?: string }) {
  const blocks: ReactNode[] = [];
  let key = 0;
  let list: { ordered: boolean; items: ReactNode[] } | null = null;
  const flush = () => {
    if (list) {
      blocks.push(list.ordered ? <ol key={`b${key++}`}>{list.items}</ol> : <ul key={`b${key++}`}>{list.items}</ul>);
      list = null;
    }
  };
  text.split("\n").forEach((raw, i) => {
    const line = raw.trimEnd();
    const ul = /^\s*[-*]\s+(.*)/.exec(line);
    const ol = /^\s*\d+\.\s+(.*)/.exec(line);
    if (ul || ol) {
      const ordered = !!ol;
      if (!list || list.ordered !== ordered) {
        flush();
        list = { ordered, items: [] };
      }
      list.items.push(<li key={i}>{inline((ul ?? ol)![1], onCite)}</li>);
      return;
    }
    flush();
    if (!line.trim()) return;
    const k = `b${key++}`;
    if (/^#{2,4} /.test(line)) blocks.push(<h4 key={k}>{inline(line.replace(/^#{2,4} /, ""), onCite)}</h4>);
    else if (line.startsWith("> ")) blocks.push(<blockquote key={k}>{inline(line.slice(2), onCite)}</blockquote>);
    else if (line === "---") blocks.push(<hr key={k} />);
    else blocks.push(<p key={k}>{inline(line, onCite)}</p>);
  });
  flush();
  return <div className={className ? `md ${className}` : "md"}>{blocks}</div>;
}

/* ------------------------------------------------------------------ AI answer structure */
export interface AnswerSection {
  key: string;
  title: string;
  body: string;
}

/** Map the labels the AI engines emit onto the investigation-report vocabulary. */
const SECTION_ALIASES: [RegExp, string, string][] = [
  [/^(summary|overview|answer|risk score)$/i, "summary", "Summary"],
  [/^(evidence|key evidence|supporting evidence)/i, "evidence", "Evidence"],
  [/^(why it scored|reasoning|why|analysis|risk contributors)/i, "reasoning", "Reasoning"],
  [/^(context|process context)/i, "context", "Context"],
  [/^(confidence)/i, "confidence", "Confidence"],
  [/^(possible interpretation|interpretation|assessment)/i, "interpretation", "Interpretation"],
  [/^(limitations?|caveats?|what (this|it) does not prove)/i, "limitations", "Limitations"],
  [/^(recommended|next steps|recommendation)/i, "recommended", "Recommended investigation"],
];

function canonical(label: string): { key: string; title: string } {
  const clean = label.replace(/[:*]/g, "").trim();
  for (const [re, key, title] of SECTION_ALIASES) if (re.test(clean)) return { key, title };
  return { key: clean.toLowerCase().replace(/\W+/g, "_"), title: clean };
}

/**
 * Split an answer into sections at `### Heading` lines and at lines that start with a bold label
 * (`**Evidence:**`). Text before the first label becomes the summary. Content is never altered,
 * only grouped - so an answer that does not follow the pattern simply renders as one summary section.
 */
export function parseAnswer(text: string): { notice: string | null; heading: string | null; sections: AnswerSection[] } {
  const lines = text.split("\n");
  let notice: string | null = null;
  let heading: string | null = null;
  const sections: AnswerSection[] = [];
  let cur: AnswerSection = { key: "summary", title: "Summary", body: "" };
  const push = () => {
    if (cur.body.trim()) sections.push({ ...cur, body: cur.body.trim() });
  };
  for (const raw of lines) {
    const line = raw.trimEnd();
    if (line.startsWith("> ") && !notice && sections.length === 0 && !cur.body.trim()) {
      notice = line.slice(2);
      continue;
    }
    const h = /^#{2,4}\s+(.*)$/.exec(line);
    if (h && !heading && sections.length === 0 && !cur.body.trim()) {
      heading = h[1];
      continue;
    }
    const bold = /^\*\*([^*]{2,48}?):\*\*\s*(.*)$/.exec(line);
    const label = bold ? { name: bold[1], rest: bold[2] } : h ? { name: h[1], rest: "" } : null;
    if (label) {
      const c = canonical(label.name);
      if (c.key !== cur.key) {
        push();
        cur = { key: c.key, title: c.title, body: label.rest ? `${label.rest}\n` : "" };
        continue;
      }
    }
    cur.body += `${line}\n`;
  }
  push();
  return { notice, heading, sections };
}
