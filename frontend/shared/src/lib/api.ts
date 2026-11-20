/** Klient REST API. Typy odpowiadają schematom z backend/app/api/schemas.py. */

export type AssetType = "host" | "domain" | "ip" | "service" | "application";
export type Exposure = "internet" | "internal";

export interface Health {
  status: "ok" | "degraded";
  version: string;
  database: boolean;
  redis: boolean;
  demo_mode: boolean;
}

export interface Asset {
  id: string;
  type: AssetType;
  name: string;
  exposure: Exposure;
  criticality: number;
  owner: string | null;
  tags: string[];
  status: "active" | "missing" | "retired" | "shadow";
  first_seen: string;
  last_seen: string;
}

export interface AssetInput {
  type: AssetType;
  name: string;
  exposure: Exposure;
  criticality: number;
  owner: string | null;
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor: string;
  action: string;
  object_type: string | null;
  object_id: string | null;
  reason: string;
  inputs: Record<string, unknown>;
  hash: string;
  prev_hash: string;
}

export interface AuditChain {
  ok: boolean;
  entries: number;
  broken_at_id: number | null;
  detail: string | null;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Scope {
  allowed_domains: string[];
  allowed_cidrs: string[];
  denied_domains: string[];
  denied_cidrs: string[];
  default_rate_per_minute: number;
  demo_mode: boolean;
  demo_lab_cidr: string;
  demo_approval_expires_at: string | null;
}

export interface ScopeCheck {
  target: string;
  allowed: boolean;
  decision: string;
  reason: string;
  resolved_ip: string | null;
  approval_source: string | null;
}

export type RiskLevel = "krytyczny" | "wysoki" | "średni" | "niski";
export type FindingStatus =
  | "open"
  | "acknowledged"
  | "in_progress"
  | "resolved"
  | "accepted_risk"
  | "false_positive";

export interface AssetRef {
  id: string;
  name: string;
  type: AssetType;
  exposure: Exposure;
  criticality: number;
  status: Asset["status"];
}

export interface VulnRef {
  cve_id: string;
  cvss_score: number | null;
  epss: number | null;
  in_kev: boolean;
  kev_due_date: string | null;
  has_public_exploit: boolean;
}

export interface Finding {
  id: string;
  type: string;
  status: FindingStatus;
  risk_score: number;
  risk_level: RiskLevel;
  summary: string;
  asset: AssetRef;
  vulnerability: VulnRef | null;
  product: string | null;
  version: string | null;
  port: number | null;
  fixed_version: string | null;
  assignee: string | null;
  first_seen: string;
  last_seen: string;
}

export interface RiskComponent {
  name: string;
  label: string;
  source: string;
  value: number;
  weight: number;
  contribution: number;
}

export interface FindingEvent {
  id: string;
  kind: string;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  actor: string;
  reason: string | null;
  created_at: string;
}

export interface FindingDetail extends Finding {
  description: string;
  references: string[];
  kev_required_action: string | null;
  risk_breakdown: {
    components: RiskComponent[];
    base_score: number;
    premiums: { rule: string; points: number; description: string }[];
    score: number;
    level: RiskLevel;
    summary: string;
    config_version: string;
  };
  evidence: Record<string, string | number | null>;
  events: FindingEvent[];
}

export interface FindingPatch {
  status?: FindingStatus;
  assignee?: string | null;
  reason?: string;
}

export interface Threat {
  cve_id: string;
  description: string;
  cvss_score: number | null;
  epss: number | null;
  in_kev: boolean;
  kev_date_added: string | null;
  has_public_exploit: boolean;
  published: string | null;
  first_ingested: string;
  is_new: boolean;
  affected_assets: {
    finding_id: string;
    asset_id: string;
    asset_name: string;
    risk_score: number;
    risk_level: RiskLevel;
  }[];
  max_risk: number | null;
}

export interface ThreatFeed {
  items: Threat[];
  total: number;
  total_ours: number;
  new_total: number;
  new_ours: number;
  new_since: string;
}

export interface FeedStatus {
  feed: string;
  mode: string | null;
  status: string;
  items_new: number;
  items_updated: number;
  error: string | null;
  finished_at: string | null;
}

export interface Software {
  id: string;
  product: string;
  version: string;
  port: number | null;
  protocol: string | null;
  raw_banner: string | null;
  cpe_vendor: string | null;
  cpe_product: string | null;
  match_status: string;
  match_method: string | null;
  match_confidence: number;
  source: string;
  last_seen: string;
}

export interface ReviewItem {
  id: string;
  cpe: string;
  score: number;
  method: string;
  reason: string;
  created_at: string;
  software: Software;
  asset: AssetRef;
}

export interface ScanAction {
  id: string;
  scan_run_id: string;
  asset_id: string | null;
  target: string;
  tool: string;
  rule_name: string;
  intrusiveness: number;
  status: string;
  approval_source: string | null;
  scope_decision: string | null;
  params: Record<string, string>;
  reason: string;
  detail: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface ScanRun {
  id: string;
  trigger: string;
  status: string;
  summary: Record<string, unknown>;
  started_at: string;
  finished_at: string | null;
  actions: ScanAction[];
}

export interface Task {
  task_id: string;
  detail: string;
}

export interface NotificationItem {
  id: string;
  finding_id: string | null;
  rule_name: string;
  channel: string;
  status: string;
  payload: {
    title?: string;
    lines?: string[];
    asset_name?: string;
    delivery?: string;
  };
  created_at: string;
}

export interface Stats {
  assets_total: number;
  assets_by_status: Record<string, number>;
  findings_active: number;
  findings_by_level: Partial<Record<RiskLevel, number>>;
  kev_active: number;
  review_queue: number;
  awaiting_approval: number;
  notifications_today: number;
  last_scan: ScanRun | null;
  feeds: FeedStatus[];
}

export interface ImportResult {
  created: number;
  updated: number;
  unchanged: number;
  errors: string[];
}

export type Audience = "technical" | "operational" | "executive";

export interface Explanation {
  finding_id: string;
  cve_id: string;
  audience: Audience;
  asset_context: string;
  text: string;
  source: "model" | "template";
  label: string;
  validation: "passed" | "rejected" | "none" | "unavailable";
  cached: boolean;
  model: string | null;
  prompt_version: string;
  created_at: string | null;
  problems: string[];
}

export interface ExplanationJob {
  job_id: string | null;
  detail: string;
  explanation: Explanation | null;
}

export interface LlmStatus {
  enabled: boolean;
  available: boolean;
  model: string;
  detail: string;
  external_enabled: boolean;
}

export type ExplanationEvent =
  | { type: "queued" | "start" | "retry" }
  | { type: "token"; text: string }
  | { type: "done"; source: string; validation: string; problems?: string[] }
  | { type: "error"; message: string };

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** Dostawca tokenu dostępu; ustawia go `AuthProvider` po zalogowaniu. */
type TokenSource = { token: () => string | null; onUnauthorized: () => void };
let tokenSource: TokenSource = { token: () => null, onUnauthorized: () => undefined };

export function setTokenSource(source: TokenSource): void {
  tokenSource = source;
}

function authHeaders(): Record<string, string> {
  const token = tokenSource.token();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...authHeaders(), ...init?.headers },
  });
  if (response.status === 401) tokenSource.onUnauthorized();
  if (!response.ok) {
    let message = `Błąd serwera (${response.status})`;
    try {
      const body: unknown = await response.json();
      if (body && typeof body === "object" && "detail" in body && typeof body.detail === "string") {
        message = body.detail;
      }
    } catch {
      // odpowiedź bez treści JSON: zostaje komunikat domyślny
    }
    throw new ApiError(response.status, message);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

/** Strumień SSE przez fetch: EventSource nie potrafi wysłać nagłówka Authorization. */
function streamEvents<E extends { type: string }>(
  path: string,
  onEvent: (event: E) => void,
  isTerminal: (event: E) => boolean,
): () => void {
  const controller = new AbortController();
  const lost = () =>
    onEvent({ type: "error", message: "Utracono połączenie ze strumieniem" } as unknown as E);
  void (async () => {
    try {
      const response = await fetch(`/api${path}`, {
        headers: { Accept: "text/event-stream", ...authHeaders() },
        signal: controller.signal,
      });
      if (!response.ok || !response.body) {
        if (response.status === 401) tokenSource.onUnauthorized();
        lost();
        return;
      }
      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += value;
        let boundary = buffer.indexOf("\n\n");
        while (boundary >= 0) {
          const chunk = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          const data = chunk
            .split("\n")
            .filter((line) => line.startsWith("data:"))
            .map((line) => line.slice(5).trimStart())
            .join("\n");
          if (data) {
            const event = JSON.parse(data) as E;
            onEvent(event);
            if (isTerminal(event)) {
              controller.abort();
              return;
            }
          }
          boundary = buffer.indexOf("\n\n");
        }
      }
    } catch (error) {
      if (!controller.signal.aborted) {
        console.warn("SSE", error);
        lost();
      }
    }
  })();
  return () => controller.abort();
}

export interface Me {
  username: string;
  display_name: string;
  email: string;
  kind: "human" | "agent" | "system";
  roles: string[];
  permissions: string[];
  mfa: boolean;
  client_id: string;
}

export const api = {
  health: () => request<Health>("/health"),
  me: () => request<Me>("/me"),
  logout: () => request<void>("/auth/logout", { method: "POST" }),
  adminConsoleAccess: () => request<void>("/console/admin").then(() => true),
  assets: () => request<Page<Asset>>("/assets?limit=500"),
  createAsset: (input: AssetInput) =>
    request<Asset>("/assets", { method: "POST", body: JSON.stringify(input) }),
  auditLog: (limit: number, offset: number) =>
    request<Page<AuditEntry>>(`/audit-log?limit=${limit}&offset=${offset}`),
  auditChain: () => request<AuditChain>("/audit-log/verify"),
  importAssets: (csv: string) =>
    request<ImportResult>("/assets/import", {
      method: "POST",
      body: JSON.stringify({ csv }),
    }),
  stats: () => request<Stats>("/stats"),
  findings: (status: string) => request<Page<Finding>>(`/findings?status=${status}&limit=500`),
  finding: (id: string) => request<FindingDetail>(`/findings/${id}`),
  updateFinding: (id: string, patch: FindingPatch) =>
    request<FindingDetail>(`/findings/${id}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),
  llmStatus: () => request<LlmStatus>("/llm/status"),
  explanation: (findingId: string, audience: Audience) =>
    request<Explanation>(`/findings/${findingId}/explanation?audience=${audience}`),
  requestExplanation: (
    findingId: string,
    body: {
      audience: Audience;
      regenerate?: boolean;
      provider?: "local" | "external";
    },
  ) =>
    request<ExplanationJob>(`/findings/${findingId}/explanation`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  /** Strumień zdarzeń generowania (SSE). Zwraca funkcję zamykającą połączenie. */
  explanationEvents: (jobId: string, onEvent: (event: ExplanationEvent) => void) =>
    streamEvents<ExplanationEvent>(
      `/explanations/jobs/${jobId}/events`,
      onEvent,
      (event) => event.type === "done" || event.type === "error",
    ),
  threatFeed: (scope: "ours" | "all") => request<ThreatFeed>(`/threat-feed?scope=${scope}`),
  syncFeeds: () => request<Task>("/feeds/sync", { method: "POST" }),
  reviewQueue: () => request<ReviewItem[]>("/review-queue"),
  decideReview: (id: string, accept: boolean) =>
    request<{ match_status: string; findings_created: number }>(`/review-queue/${id}/decision`, {
      method: "POST",
      body: JSON.stringify({ accept }),
    }),
  scans: () => request<ScanRun[]>("/scans?limit=5"),
  triggerScan: () => request<Task>("/scans", { method: "POST" }),
  scanActions: (status: string) => request<ScanAction[]>(`/scan-actions?status=${status}`),
  approveAction: (id: string, reason: string) =>
    request<Task>(`/scan-actions/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  rejectAction: (id: string, reason: string) =>
    request<ScanAction>(`/scan-actions/${id}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  notifications: () => request<NotificationItem[]>("/notifications?limit=20"),
  scope: () => request<Scope>("/scope"),
  checkScope: (target: string, intrusiveness: 1 | 2 | 3) =>
    request<ScopeCheck>("/scope/check", {
      method: "POST",
      body: JSON.stringify({ target, intrusiveness }),
    }),
};
