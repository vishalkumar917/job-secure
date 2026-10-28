import { Bot, Command, FileText, FolderPlus, Gauge, HardDrive, ScanSearch, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { Page } from "../components/layout/AppLayout";
import { useCrumbs } from "../components/layout/crumbs";
import { Button, Card, Kbd, Notice, PageHeader, SectionHeader } from "../components/ui";

const WORKFLOW: { icon: ReactNode; title: string; text: string }[] = [
  { icon: <FolderPlus />, title: "Open an investigation", text: "Record the scope, source and authorisation. Opening a case starts its chain of custody." },
  { icon: <HardDrive />, title: "Add a memory image", text: "Upload .raw, .mem, .vmem or .dmp. The file is validated, hashed (SHA-256) and stored read-only." },
  { icon: <ScanSearch />, title: "Run the analysis", text: "Volatility 3 plugins run in stages; suspicious processes get a targeted deep dive. The hash is re-verified before and after." },
  { icon: <Gauge />, title: "Triage findings", text: "Review the risk score, its contributors and each finding's evidence. Mark findings as investigating, confirmed or false positive." },
  { icon: <Bot />, title: "Ask the AI assistant", text: "Ask questions in plain language. Answers cite stored evidence and are validated - never treated as proof on their own." },
  { icon: <FileText />, title: "Report", text: "Generate PDF, HTML, JSON or CSV reports. Each report is hashed and recorded in the chain of custody." },
];

const SHORTCUTS: [ReactNode, string][] = [
  [<><Kbd>Ctrl</Kbd><Kbd>K</Kbd></>, "Open search / command palette"],
  [<Kbd>/</Kbd>, "Open search"],
  [<Kbd>[</Kbd>, "Collapse or expand the sidebar"],
  [<><Kbd>↑</Kbd><Kbd>↓</Kbd><Kbd>Enter</Kbd></>, "Move through and open search results"],
  [<Kbd>Esc</Kbd>, "Close dialogs, drawers and menus"],
  [<><Kbd>←</Kbd><Kbd>→</Kbd></>, "Switch between tabs"],
  [<><Kbd>Ctrl</Kbd><span className="text-xs text-muted">+ scroll</span></>, "Zoom the process graph"],
];

const GLOSSARY: [string, string][] = [
  ["pslist / psscan", "The OS's active process list versus a pool-tag scan of memory. A process only found by psscan may be hidden or terminated."],
  ["malfind", "Finds private memory that is executable - a common indicator of code injection, but also produced by JIT compilers."],
  ["VAD", "Virtual Address Descriptor - the kernel's record of a process's memory regions, their protection and backing file."],
  ["RWX", "Read-write-execute protection. Legitimate code rarely needs memory that is both writable and executable."],
  ["IOC", "Indicator of compromise - an IP, domain, URL, hash, path or command worth checking against threat intelligence."],
  ["Risk score", "0-100 prioritisation score built from rule points weighted by confidence, capped per category. Not a malware verdict."],
];

export default function HelpPage() {
  useCrumbs([{ label: "Administration" }, { label: "Help" }]);
  return (
    <Page className="max-w-[1200px]">
      <PageHeader title="Help & shortcuts" subtitle="How MemTrace turns a Windows memory image into explainable, evidence-backed findings." />

      <section className="mb-12">
        <SectionHeader title="Investigation workflow" />
        <ol className="grid gap-5 sm:grid-cols-2 xl:grid-cols-3">
          {WORKFLOW.map((w, i) => (
            <li key={w.title} className="rounded-2xl border border-line bg-surface p-6 shadow-card">
              <div className="flex items-center gap-3">
                <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent-soft text-accent-text [&_svg]:h-5 [&_svg]:w-5">{w.icon}</span>
                <span className="font-mono text-xs text-faint">STEP {String(i + 1).padStart(2, "0")}</span>
              </div>
              <h3 className="mt-5 text-[15px] font-semibold text-ink">{w.title}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{w.text}</p>
            </li>
          ))}
        </ol>
      </section>

      <div className="grid gap-6 lg:grid-cols-12">
        <Card className="lg:col-span-5 lg:self-start" title="Keyboard shortcuts" icon={<Command />}>
          <ul className="divide-y divide-line">
            {SHORTCUTS.map(([k, label], i) => (
              <li key={i} className="flex items-center justify-between gap-4 py-3 text-sm first:pt-0 last:pb-0">
                <span className="text-ink-2">{label}</span><span className="flex shrink-0 items-center gap-1">{k}</span>
              </li>
            ))}
          </ul>
        </Card>
        <Card className="lg:col-span-7" title="Glossary">
          <dl className="space-y-5">
            {GLOSSARY.map(([t, d]) => (
              <div key={t}><dt className="text-sm font-semibold text-ink">{t}</dt><dd className="mt-1 text-sm leading-relaxed text-muted">{d}</dd></div>
            ))}
          </dl>
        </Card>
      </div>

      <Notice tone="ok" className="mt-8" title="Defensive use only" action={<Button size="sm" to="/investigations/new">Start an investigation</Button>}>
        <span className="inline-flex items-center gap-1.5"><ShieldCheck className="h-4 w-4" />MemTrace only analyses forensic evidence. Uploaded memory images are treated as untrusted input and never executed.</span>
      </Notice>
    </Page>
  );
}
