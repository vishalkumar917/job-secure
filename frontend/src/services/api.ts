import type {
  AIAnswer,
  AISettings,
  Case,
  CaseDetail,
  ChatMessage,
  Connection,
  CustodyEvent,
  Dashboard,
  Explanation,
  Finding,
  ImageInfo,
  IOC,
  Job,
  JobDetail,
  Module,
  PluginRun,
  Process,
  ProcessDetail,
  Region,
  Report,
  Rule,
  ScoringModel,
  SystemStatus,
  TimelineEvent,
  TreeNode,
  User,
  YaraMatch,
  YaraRuleFile,
} from "../types";

const BASE = import.meta.env.VITE_API_BASE ?? "";
const TOKEN_KEY = "memtrace.token";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export const tokenStore = {
  get: () => sessionStorage.getItem(TOKEN_KEY),
  set: (t: string) => sessionStorage.setItem(TOKEN_KEY, t),
  clear: () => sessionStorage.removeItem(TOKEN_KEY),
};

type Query = Record<string, string | number | boolean | string[] | undefined | null>;

function qs(params?: Query): string {
  if (!params) return "";
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, x));
    else sp.append(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

async function request<T>(method: string, path: string, opts: { query?: Query; body?: unknown; form?: FormData } = {}): Promise<T> {
  const headers: Record<string, string> = {};
  const token = tokenStore.get();
  if (token) headers.Authorization = `Bearer ${token}`;
  let body: BodyInit | undefined;
  if (opts.form) body = opts.form;
  else if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  const res = await fetch(`${BASE}${path}${qs(opts.query)}`, { method, headers, body });
  if (res.status === 401 && !path.startsWith("/api/auth/login")) {
    tokenStore.clear();
    window.dispatchEvent(new Event("memtrace:logout"));
  }
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const data = await res.json();
      msg = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail ?? data);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, msg || `Request failed (${res.status})`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** Downloads go through fetch so the bearer token is sent; the browser then saves the blob. */
export async function download(path: string, query?: Query, fallbackName = "download"): Promise<void> {
  const token = tokenStore.get();
  const res = await fetch(`${BASE}${path}${qs(query)}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  if (!res.ok) throw new ApiError(res.status, `Download failed (${res.status})`);
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") ?? "";
  const name = /filename="?([^"]+)"?/.exec(cd)?.[1] ?? fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const A = (analysisId: number) => ({ analysis_id: analysisId });

export const api = {
  login: (username: string, password: string) =>
    request<{ access_token: string; user: User }>("POST", "/api/auth/login", { body: { username, password } }),
  me: () => request<User>("GET", "/api/auth/me"),

  dashboard: () => request<Dashboard>("GET", "/api/dashboard"),
  systemStatus: () => request<SystemStatus>("GET", "/api/system/status"),
  scoringModel: () => request<ScoringModel>("GET", "/api/scoring/model"),

  cases: () => request<Case[]>("GET", "/api/cases"),
  case: (id: number) => request<CaseDetail>("GET", `/api/cases/${id}`),
  createCase: (body: { title: string; description: string; case_number?: string }) => request<Case>("POST", "/api/cases", { body }),
  updateCase: (id: number, body: { status?: string; title?: string; description?: string }) =>
    request<Case>("PATCH", `/api/cases/${id}`, { body }),
  custody: (caseId: number) => request<CustodyEvent[]>("GET", `/api/cases/${caseId}/custody`),

  verifyImage: (id: number) =>
    request<{ match: boolean; intake_sha256: string; current_sha256: string }>("POST", `/api/memory/${id}/verify`),
  startAnalysis: (imageId: number, yara: boolean) => request<Job>("POST", `/api/analysis/${imageId}/start`, { body: { yara } }),
  loadDemo: () => request<Job>("POST", "/api/demo/load"),
  jobStatus: (id: number) => request<Job>("GET", `/api/analysis/${id}/status`),
  job: (id: number) => request<JobDetail>("GET", `/api/analysis/${id}`),
  plugins: (id: number) => request<PluginRun[]>("GET", `/api/analysis/${id}/plugins`),

  processes: (id: number, q: Query = {}) => request<Process[]>("GET", "/api/processes", { query: { ...A(id), ...q } }),
  tree: (id: number) => request<TreeNode[]>("GET", "/api/processes/tree", { query: A(id) }),
  process: (id: number, pid: number) => request<ProcessDetail>("GET", `/api/processes/${pid}`, { query: A(id) }),
  network: (id: number) => request<Connection[]>("GET", "/api/network", { query: A(id) }),
  regions: (id: number, q: Query = {}) => request<Region[]>("GET", "/api/memory-regions", { query: { ...A(id), ...q } }),
  modules: (id: number, q: Query = {}) => request<Module[]>("GET", "/api/modules", { query: { ...A(id), ...q } }),
  timeline: (id: number) => request<TimelineEvent[]>("GET", "/api/timeline", { query: A(id) }),
  yaraMatches: (id: number) => request<YaraMatch[]>("GET", "/api/yara/matches", { query: A(id) }),
  findings: (id: number, q: Query = {}) => request<Finding[]>("GET", "/api/findings", { query: { ...A(id), ...q } }),
  updateFinding: (fid: number, status: string) => request<Finding>("PATCH", `/api/findings/${fid}`, { body: { status } }),
  explanation: (fid: number, regenerate = false) =>
    request<Explanation>("GET", `/api/findings/${fid}/explanation`, { query: { regenerate } }),
  iocs: (id: number) => request<IOC[]>("GET", "/api/iocs", { query: A(id) }),

  aiQuery: (analysisId: number, question: string) =>
    request<AIAnswer>("POST", "/api/ai/query", { body: { analysis_id: analysisId, question } }),
  aiHistory: (id: number) => request<ChatMessage[]>("GET", "/api/ai/history", { query: A(id) }),
  aiSummary: (id: number) =>
    request<{ markdown: string; provider: string; validation: Record<string, unknown> }>("GET", "/api/ai/summary", { query: A(id) }),

  reports: (id: number) => request<Report[]>("GET", "/api/reports", { query: A(id) }),
  generateReport: (analysisId: number, format: string) =>
    request<Report>("POST", "/api/reports/generate", { body: { analysis_id: analysisId, format } }),

  rules: () => request<Rule[]>("GET", "/api/rules"),
  toggleRule: (ruleId: string, enabled: boolean) => request<Rule>("PATCH", `/api/rules/${ruleId}`, { body: { enabled } }),
  yaraRules: () => request<YaraRuleFile[]>("GET", "/api/yara/rules"),
  toggleYara: (id: number, enabled: boolean) => request<YaraRuleFile>("PATCH", `/api/yara/rules/${id}`, { body: { enabled } }),
  deleteYara: (id: number) => request<void>("DELETE", `/api/yara/rules/${id}`),
  uploadYara: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<YaraRuleFile>("POST", "/api/yara/rules", { form });
  },
  aiSettings: () => request<AISettings>("GET", "/api/settings/ai"),
  saveAiSettings: (body: Omit<AISettings, "api_key_configured">) => request<AISettings>("PUT", "/api/settings/ai", { body }),
  testAi: () => request<{ ok: boolean; detail: string }>("POST", "/api/settings/ai/test"),
};

/** Upload with progress (fetch has no upload progress events). */
export function uploadImage(caseId: number, file: File, onProgress: (pct: number) => void): Promise<ImageInfo> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${BASE}/api/memory/upload`);
    const token = tokenStore.get();
    if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`);
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(Math.round((e.loaded / e.total) * 100));
    xhr.onload = () => {
      let data: { detail?: string } & Partial<ImageInfo> = {};
      try {
        data = JSON.parse(xhr.responseText);
      } catch {
        /* ignore */
      }
      if (xhr.status >= 200 && xhr.status < 300) resolve(data as ImageInfo);
      else reject(new ApiError(xhr.status, typeof data.detail === "string" ? data.detail : `Upload failed (${xhr.status})`));
    };
    xhr.onerror = () => reject(new ApiError(0, "Network error during upload"));
    const form = new FormData();
    form.append("case_id", String(caseId));
    form.append("file", file);
    xhr.send(form);
  });
}
