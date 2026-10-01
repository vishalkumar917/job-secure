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

export const STAGES: { key: string; label: string }[] = [
  { key: "integrity_check", label: "Integrity check" },
  { key: "identification", label: "Image identification" },
  { key: "process_enumeration", label: "Process enumeration" },
  { key: "execution_context", label: "Command lines & modules" },
  { key: "network", label: "Network" },
  { key: "injection_detection", label: "Injection detection" },
  { key: "triage", label: "Triage" },
  { key: "deep_dive", label: "Targeted deep dive" },
  { key: "yara", label: "YARA" },
  { key: "correlation", label: "Detection & correlation" },
  { key: "persisting", label: "Storing evidence" },
  { key: "ai_summary", label: "AI summary" },
  { key: "completed", label: "Completed" },
];
