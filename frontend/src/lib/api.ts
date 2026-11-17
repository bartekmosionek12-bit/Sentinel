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

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
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
  return (await response.json()) as T;
}

export const api = {
  health: () => request<Health>("/health"),
  assets: () => request<Page<Asset>>("/assets?limit=500"),
  createAsset: (input: AssetInput) =>
    request<Asset>("/assets", { method: "POST", body: JSON.stringify(input) }),
  auditLog: (limit: number, offset: number) =>
    request<Page<AuditEntry>>(`/audit-log?limit=${limit}&offset=${offset}`),
  auditChain: () => request<AuditChain>("/audit-log/verify"),
  scope: () => request<Scope>("/scope"),
  checkScope: (target: string, intrusiveness: 0 | 1 | 2) =>
    request<ScopeCheck>("/scope/check", {
      method: "POST",
      body: JSON.stringify({ target, intrusiveness }),
    }),
};
