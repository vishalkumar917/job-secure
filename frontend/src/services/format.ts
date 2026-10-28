export function fmtBytes(n: number | null | undefined): string {
  if (n == null) return "-";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/** All forensic timestamps are displayed in UTC to avoid time-zone ambiguity. */
export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "unknown";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z").replace("Z", " UTC");
}

export function fmtDuration(ms: number | null | undefined): string {
  if (ms == null) return "-";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

export function pct(v: number): string {
  return `${Math.round(v * 100)}%`;
}

export function confidenceLabel(v: number): "High" | "Medium" | "Low" {
  return v >= 0.75 ? "High" : v >= 0.5 ? "Medium" : "Low";
}

export const STAGES: { key: string; label: string; detail: string }[] = [
  { key: "integrity_check", label: "Evidence integrity", detail: "Re-hash the image (SHA-256) and compare with the intake hash" },
  { key: "identification", label: "OS identification", detail: "windows.info - kernel, build, architecture, symbols" },
  { key: "process_enumeration", label: "Process enumeration", detail: "pslist x psscan x pstree cross-view" },
  { key: "execution_context", label: "Command lines & DLLs", detail: "cmdline, dlllist, ldrmodules" },
  { key: "network", label: "Network analysis", detail: "netscan endpoints and owning processes" },
  { key: "injection_detection", label: "Memory injection detection", detail: "malfind - private executable memory" },
  { key: "triage", label: "Triage", detail: "Rank processes for the targeted deep dive" },
  { key: "deep_dive", label: "Targeted deep dive", detail: "vadinfo, handles, SIDs, privileges per triaged PID" },
  { key: "yara", label: "YARA scanning", detail: "vadyarascan with enabled rule files" },
  { key: "correlation", label: "Detection & IOC correlation", detail: "Rule engine, risk scoring, IOC extraction" },
  { key: "persisting", label: "Storing evidence", detail: "Persist artifacts, findings and timeline" },
  { key: "ai_summary", label: "AI investigation summary", detail: "Grounded summary from stored evidence" },
  { key: "completed", label: "Completed", detail: "Evidence re-verified after analysis" },
];

/** "2 minutes ago" - for recency hints only; forensic timestamps are always shown in UTC alongside. */
export function fmtRelative(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.round((now - t) / 1000);
  if (s < 45) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} minute${m === 1 ? "" : "s"} ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} hour${h === 1 ? "" : "s"} ago`;
  const d = Math.round(h / 24);
  if (d < 30) return `${d} day${d === 1 ? "" : "s"} ago`;
  return fmtDate(iso);
}

/** HH:MM:SS (UTC). */
export function fmtClock(iso: string | null | undefined): string {
  if (!iso) return "--:--:--";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(11, 19);
}

/** YYYY-MM-DD (UTC). */
export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "unknown";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 10);
}

/** Elapsed time as m:ss or h:mm:ss. */
export function fmtElapsed(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const ss = String(s % 60).padStart(2, "0");
  return h ? `${h}:${String(m).padStart(2, "0")}:${ss}` : `${m}:${ss}`;
}

export function titleCase(s: string): string {
  return s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export const CATEGORY_LABEL: Record<string, string> = {
  memory: "Memory injection",
  modules: "Modules / DLLs",
  network: "Network",
  commandline: "Command line",
  ioc: "IOC watchlist",
  parent_child: "Parent / child",
  privileges: "Privileges & handles",
  yara: "YARA",
  masquerading: "Masquerading",
  process_integrity: "Process integrity",
  path: "Execution path",
};

export const IOC_TYPE_LABEL: Record<string, string> = {
  ipv4: "IP address", ipv6: "IP address", domain: "Domain", url: "URL", md5: "Hash", sha1: "Hash", sha256: "Hash",
  file_path: "File path", command: "Command", dll: "DLL", process_name: "Process name", yara_rule: "YARA rule",
  mutex: "Mutex", registry_key: "Registry key", email: "Email",
};

/** Investigator triage states (API values are fixed; these are display labels). */
export const FINDING_STATUS: { value: string; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "needs_review", label: "Investigating" },
  { value: "confirmed", label: "Confirmed" },
  { value: "false_positive", label: "False positive" },
];
export const findingStatusLabel = (v: string) => FINDING_STATUS.find((s) => s.value === v)?.label ?? titleCase(v);

/** Decode a PowerShell -EncodedCommand argument (base64 of UTF-16LE) for display. Returns null if absent/invalid. */
export function decodePowerShell(cmdline: string | null | undefined): string | null {
  if (!cmdline) return null;
  const m = /\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+([A-Za-z0-9+/=]{8,})/i.exec(cmdline);
  if (!m) return null;
  try {
    const bin = atob(m[1]);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder("utf-16le").decode(bytes);
  } catch {
    return null;
  }
}
