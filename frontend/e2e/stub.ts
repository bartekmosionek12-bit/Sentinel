/** Podstawione API dla testów interfejsu: odpowiedzi z e2e/fixtures, zapis wysłanych żądań. */
import { readFileSync } from "node:fs";
import path from "node:path";

import type { Page } from "@playwright/test";

const DIR = path.join(import.meta.dirname, "fixtures");

function fixture(name: string): unknown {
  return JSON.parse(readFileSync(path.join(DIR, `${name}.json`), "utf8"));
}

const ROUTES: [RegExp, string][] = [
  [/^\/api\/me/, "me"],
  [/^\/api\/health/, "health"],
  [/^\/api\/stats/, "stats"],
  [/^\/api\/inbox/, "inbox"],
  [/^\/api\/findings\?.*asset_id/, "device_findings"],
  [/^\/api\/findings/, "findings"],
  [/^\/api\/org\/overview/, "overview"],
  [/^\/api\/org\/devices\?unknown/, "unknown"],
  [/^\/api\/org\/devices\?pseudonyms/, "devices_p"],
  [/^\/api\/org\/devices\//, "device"],
  [/^\/api\/org\/devices/, "devices"],
  [/^\/api\/org\/people/, "people"],
  [/^\/api\/freshness/, "freshness"],
  [/^\/api\/scan-requests/, "scanreq"],
];

export interface Sent {
  method: string;
  path: string;
  body: unknown;
}

export const ADMIN_ME = {
  username: "admin",
  display_name: "Admin",
  email: "admin@sentinel.example",
  kind: "human",
  roles: ["admin"],
  permissions: ["*"],
  mfa: true,
  client_id: "sentinel-admin",
};

/** Loguje „menedżera” (albo admina) i podstawia API. Zwraca listę wysłanych POST-ów. */
export async function stubApi(
  page: Page,
  { app = "dashboard", tourDone = true }: { app?: "dashboard" | "admin"; tourDone?: boolean } = {},
): Promise<Sent[]> {
  const sent: Sent[] = [];
  const answers = fixture("assistant") as Record<string, unknown>;
  const me = app === "admin" ? { ...ADMIN_ME, permissions: adminPermissions() } : fixture("me");
  await page.route("**/auth/**", (route) => route.abort());
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const where = url.pathname + url.search;
    const body = request.postDataJSON?.() ?? null;
    if (request.method() !== "GET") sent.push({ method: request.method(), path: url.pathname, body });
    if (url.pathname === "/api/assistant") {
      const question = String((body as { question?: string })?.question ?? "");
      const answer = answers[question] ?? answers["Wyłącz serwer web-01"];
      return route.fulfill({ json: answer });
    }
    if (request.method() === "POST" && url.pathname === "/api/scan-requests") {
      return route.fulfill({ status: 201, json: { ...(fixture("scanreq") as object[])[0], id: "new" } });
    }
    if (request.method() === "POST" && url.pathname.endsWith("/decision")) {
      return route.fulfill({ json: { ...(fixture("scanreq") as object[])[0], status: "approved" } });
    }
    if (url.pathname === "/api/me") return route.fulfill({ json: me });
    const hit = ROUTES.find(([pattern]) => pattern.test(where));
    if (!hit) return route.fulfill({ json: [] });
    let data = fixture(hit[1]);
    if (hit[1] === "health") data = { ...(data as object), demo_mode: true };
    return route.fulfill({ json: data });
  });
  const client = app === "admin" ? "sentinel-admin" : "sentinel-dashboard";
  await page.addInitScript(
    ({ client, tourDone }) => {
      sessionStorage.setItem(
        `oidc.user:${location.origin}/auth/realms/sentinel:${client}`,
        JSON.stringify({
          access_token: "test",
          token_type: "Bearer",
          scope: "openid",
          profile: { sub: "t", preferred_username: client === "sentinel-admin" ? "admin" : "manager" },
          expires_at: Math.floor(Date.now() / 1000) + 3600,
        }),
      );
      if (tourDone) localStorage.setItem("sentinel.tour.done.manager", "1");
    },
    { client, tourDone },
  );
  return sent;
}

function adminPermissions(): string[] {
  return [
    "console:admin",
    "inventory:read",
    "findings:read",
    "reports:read",
    "scan:read",
    "scan:run",
    "scope:read",
    "audit:read",
    "agent:read",
    "review:read",
    "notifications:read",
    "secrets:redacted:view",
    "personal_data:view",
  ];
}
