export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type RiskBand = "critical" | "high" | "moderate" | "low";

export interface User {
  id: number;
  username: string;
  full_name: string;
  role: string;
}

export interface ImageInfo {
  id: number;
  case_id: number;
  original_filename: string;
  size_bytes: number;
  sha256: string;
  format_hint: string;
  validation_notes: string[];
  is_demo: boolean;
  uploaded_at: string;
  os_info: OsInfo;
}

export interface OsInfo {
  os_name?: string | null;
  nt_version?: string | null;
  build?: number | null;
  architecture?: string | null;
  kernel_base?: string | null;
  suggested_symbols?: string | null;
  system_time?: string | null;
  confidence?: string;
  uncertain?: string[];
  note?: string;
}

export interface Job {
  id: number;
  image_id: number;
  status: string;
  stage: string;
  progress: number;
  error: string | null;
  options: Record<string, unknown>;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  hash_verified_before: boolean | null;
  hash_verified_after: boolean | null;
  overall_risk_score: number | null;
  overall_risk_band: RiskBand | null;
  volatility_version: string | null;
}

export interface JobSummary {
  total_processes: number;
  live_processes: number;
  terminated_processes: number;
  hidden_candidates: number;
  suspicious_processes: number;
  network_connections: number;
  external_connections: number;
  suspicious_connections: number;
  injected_memory_indicators: number;
  modules: number;
  iocs: number;
  findings: number;
  high_severity_findings: number;
  severity_counts: Record<Severity, number>;
  category_counts: Record<string, number>;
  risk_distribution: Record<string, number>;
  overall_risk_score: number;
  overall_risk_band: RiskBand;
  plugins_available: string[];
  plugin_failures: Record<string, string>;
  rules_not_evaluated: Record<string, string>;
  rule_errors: Record<string, string>;
  synthetic: boolean;
  scoring_model: ScoringModel;
}

export interface JobDetail extends Job {
  summary: Partial<JobSummary>;
  image: ImageInfo;
  case_id: number;
  case_number: string;
  case_title: string;
}

export interface Case {
  id: number;
  case_number: string;
  title: string;
  description: string;
  status: string;
  is_demo: boolean;
  created_at: string;
  updated_at: string;
  investigator: User | null;
}

export interface CaseDetail extends Case {
  images: ImageInfo[];
  jobs: Job[];
}

export interface CustodyEvent {
  id: number;
  action: string;
  actor: string;
  timestamp: string;
  details: string;
  sha256: string | null;
  image_id: number | null;
  job_id: number | null;
}

export interface PluginRun {
  id: number;
  plugin: string;
  stage: string;
  rationale: string;
  args: string[];
  status: string;
  started_at: string | null;
  ended_at: string | null;
  duration_ms: number | null;
  row_count: number;
  error: string | null;
  output_sha256: string | null;
}

export interface Contributor {
  points: number;
  label: string;
  rule_id: string | null;
  category: string;
  base_points?: number;
  confidence?: number;
}

export interface Process {
  id: number;
  pid: number;
  ppid: number | null;
  name: string;
  path: string | null;
  cmdline: string | null;
  create_time: string | null;
  exit_time: string | null;
  threads: number | null;
  handle_count: number | null;
  session_id: number | null;
  wow64: boolean | null;
  offset: string | null;
  in_pslist: boolean;
  in_psscan: boolean;
  in_pstree: boolean;
  is_hidden_candidate: boolean;
  is_terminated: boolean;
  deep_scanned: boolean;
  risk_score: number;
  risk_band: RiskBand;
  risk_contributors: Contributor[];
}

export interface TreeNode {
  id: number;
  pid: number;
  ppid: number | null;
  name: string;
  risk_score: number;
  risk_band: RiskBand;
  hidden: boolean;
  terminated: boolean;
  anomalous_parent: boolean;
  path: string | null;
  subtree_risk: number;
  children: TreeNode[];
}

export interface Module {
  id: number;
  pid: number;
  name: string;
  path: string | null;
  base: string | null;
  size: number | null;
  load_time: string | null;
  in_load: boolean | null;
  in_init: boolean | null;
  in_mem: boolean | null;
  is_suspicious: boolean;
  reason: string;
}

export interface Connection {
  id: number;
  pid: number | null;
  owner: string | null;
  protocol: string;
  local_addr: string | null;
  local_port: number | null;
  foreign_addr: string | null;
  foreign_port: number | null;
  state: string | null;
  created: string | null;
  is_external: boolean;
  is_suspicious: boolean;
  reason: string;
}

export interface Region {
  id: number;
  pid: number;
  process_name: string | null;
  source: string;
  start: string;
  end: string;
  protection: string | null;
  tag: string | null;
  private_memory: boolean | null;
  commit_charge: number | null;
  mapped_file: string | null;
  has_pe_header: boolean;
  hexdump: string | null;
  disasm: string | null;
  notes: string | null;
}

export interface Handle {
  id: number;
  pid: number;
  handle_value: string | null;
  handle_type: string | null;
  granted_access: string | null;
  name: string | null;
}

export interface EvidenceItem {
  source: string;
  artifact: string;
  description: string;
  value: string;
  ref: string | null;
}

export interface Finding {
  id: number;
  rule_id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: number;
  finding: string;
  evidence: EvidenceItem[];
  recommendation: string;
  pid: number | null;
  process_name: string | null;
  process_id: number | null;
  points: number;
  attack_techniques: string[];
  status: string;
}

export interface ProcessDetail {
  process: Process;
  parent: Process | null;
  children: Process[];
  modules: Module[];
  network: Connection[];
  regions: Region[];
  handles: Handle[];
  findings: Finding[];
  sids: { sid: string; name: string | null }[];
  privileges: { privilege: string; attributes: string; enabled: boolean }[];
}

export interface IOC {
  id: number;
  ioc_type: string;
  value: string;
  source: string;
  pid: number | null;
  process_name: string | null;
  confidence: "low" | "medium" | "high";
  context: string;
  watchlist_match: boolean;
}

export interface TimelineEvent {
  id: number;
  timestamp: string | null;
  timestamp_source: string;
  pid: number | null;
  process_name: string | null;
  event_type: string;
  description: string;
  evidence_ref: string | null;
  severity: Severity;
}

export interface YaraMatch {
  id: number;
  pid: number | null;
  process_name: string | null;
  rule_name: string;
  offset: string | null;
  component: string | null;
  matched_value: string | null;
  severity: Severity;
}

export interface YaraRuleFile {
  id: number;
  filename: string;
  sha256: string;
  rule_names: string[];
  builtin: boolean;
  enabled: boolean;
  uploaded_at: string;
}

export interface Rule {
  rule_id: string;
  title: string;
  category: string;
  default_severity: Severity;
  base_points: number;
  description: string;
  attack_techniques: string[];
  enabled: boolean;
}

export interface Validation {
  status: "grounded" | "uncertain" | "rejected";
  grounded: boolean;
  citations: string[];
  unknown_citations: string[];
  unsupported_entities: string[];
  overclaims: string[];
  warnings: string[];
}

export interface Citation {
  id: string;
  kind: string;
  title: string;
  pid: number | null;
}

export interface AIAnswer {
  answer: string;
  citations: Citation[];
  validation: Validation;
  provider: string;
  intents: string[];
  retrieved: number;
  message_id: number | null;
}

export interface ChatMessage {
  id: number;
  role: "user" | "assistant";
  content: string;
  citations: Citation[];
  validation: Partial<Validation>;
  provider: string | null;
  created_at: string;
}

export interface Explanation {
  finding_id: number;
  provider: string;
  model: string | null;
  content: {
    what_happened: string;
    why_suspicious: string;
    evidence: EvidenceItem[];
    confidence: { level: string; value: number; basis: string };
    possible_interpretation: string;
    does_not_prove: string;
    recommended_next_steps: string;
  };
  validation: Partial<Validation>;
  grounded: boolean;
  created_at: string;
}

export interface Report {
  id: number;
  job_id: number;
  report_format: "pdf" | "html" | "json" | "csv";
  sha256: string;
  size_bytes: number;
  generated_at: string;
}

export interface ScoringModel {
  formula: string;
  category_caps: Record<string, number>;
  corroboration: { min_categories: number; bonus: number };
  bands: { name: string; min: number; max: number }[];
  disclaimer: string;
}

export interface SystemStatus {
  volatility: { available: boolean; version: string | null; message?: string };
  yara_python: boolean;
  ai: { provider: string; model: string | null; base_url: string | null };
  limits: { max_upload_bytes: number; allowed_extensions: string[]; plugin_timeout_seconds: number; deep_scan_max_pids: number };
  demo_available: boolean;
}

export interface AISettings {
  provider: "deterministic" | "openai" | "ollama";
  base_url: string;
  model: string;
  temperature: number;
  api_key_configured: boolean;
}

export interface Dashboard {
  cases: number;
  open_cases: number;
  images: number;
  analyses: number;
  running: number;
  totals: Record<string, number>;
  severity_counts: Record<Severity, number>;
  risk_bands: Record<string, number>;
  recent_analyses: {
    id: number;
    status: string;
    progress: number;
    stage: string;
    risk_score: number | null;
    risk_band: RiskBand | null;
    image: string;
    is_demo: boolean;
    case_id: number;
    case_number: string;
    created_at: string;
  }[];
  recent_custody: { action: string; actor: string; timestamp: string; details: string; case_id: number }[];
}
