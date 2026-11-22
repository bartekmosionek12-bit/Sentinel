import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import { PageHeader } from "@shared/components/page";
import { KevBadge, RiskBadge } from "@shared/components/risk";
import { Badge } from "@shared/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@shared/components/ui/card";
import { Table, Td, Th } from "@shared/components/ui/table";
import { api, type RiskLevel } from "@shared/lib/api";
import { formatDateTime } from "@shared/lib/utils";

import { HOST_STATE } from "@/labels";
import { RunsTable } from "@/pages/Discovery";

const LEVELS: RiskLevel[] = ["krytyczny", "wysoki", "średni", "niski"];

/** Karta wskaźnika w górnym pasku: liczba, podpowiedź i link do widoku ze szczegółami. */
function Stat({
  label,
  value,
  hint,
  to,
  badge,
  tone = "primary",
}: {
  label: string;
  value: string;
  hint: string;
  to: string;
  badge?: ReactNode;
  tone?: "primary" | "danger" | "warn";
}) {
  const color = {
    primary: "text-primary",
    danger: "text-red-500",
    warn: "text-amber-400",
  }[tone];
  return (
    <Link
      to={to}
      title={hint}
      className="block rounded-md border border-border bg-card px-4 py-3 hover:border-primary"
    >
      <div className="flex items-start justify-between gap-2">
        <p className="text-sm font-semibold">{label}</p>
        {badge}
      </div>
      <p className={`mt-2 text-4xl font-bold tabular-nums ${color}`}>{value}</p>
      <p className="mt-1 text-xs text-muted-foreground">{hint}</p>
    </Link>
  );
}

function MiniStat({
  label,
  value,
  to,
}: {
  label: string;
  value: string;
  to: string;
}) {
  return (
    <Link
      to={to}
      className="block border-l-2 border-primary/60 px-3 py-1 hover:bg-muted"
    >
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-xl font-semibold tabular-nums">{value}</p>
    </Link>
  );
}

/** Discovery i sieć: liczby z ostatniego przebiegu, ostatnie przebiegi i to, co wymaga uwagi. */
function DiscoveryOverview() {
  const runs = useQuery({
    queryKey: ["discovery-runs"],
    queryFn: api.discoveryRuns,
    refetchInterval: 5000,
  });
  const done = (runs.data ?? []).filter((r) => r.status === "done");
  const [latest, previous] = done;
  const hosts = useQuery({
    queryKey: ["discovery-hosts", latest?.id],
    queryFn: () => api.discoveryHosts(latest?.id ?? ""),
    enabled: Boolean(latest),
  });
  const diff = useQuery({
    queryKey: ["compare", previous?.id, latest?.id],
    queryFn: () => api.compareRuns(previous?.id ?? "", latest?.id ?? ""),
    enabled: Boolean(latest && previous),
  });
  const states = useQuery({
    queryKey: ["host-states"],
    queryFn: api.hostStates,
  });
  const dojo = useQuery({ queryKey: ["dojo-status"], queryFn: api.dojoStatus });
  const list = hosts.data ?? [];
  const services = list.reduce((sum, h) => sum + h.services.length, 0);
  const panels = list.filter((h) => h.flags.some((f) => f.kind === "panel"));
  const staging = list.filter((h) => h.flags.some((f) => f.kind === "staging"));
  const d = diff.data?.counts;
  const unstable = Object.entries(states.data?.hosts ?? {}).filter(
    ([, v]) => v.state === "unstable",
  );
  const unstableLabel = HOST_STATE.unstable?.label ?? "Niestabilny";

  return (
    <section className="mt-6" aria-label="Discovery i sieć">
      <h2 className="mb-3 text-base font-semibold">Discovery i sieć</h2>
      {latest ? (
        <div className="grid grid-cols-2 gap-2 lg:grid-cols-4" data-demo="kpis">
          <MiniStat
            label={`Aktywne hosty (z ${latest.addresses_total.toLocaleString("pl-PL")} adresów)`}
            value={String(latest.hosts_up)}
            to={`/discovery/${latest.id}`}
          />
          <MiniStat
            label={`Otwarte usługi (panele ${panels.length}, staging ${staging.length})`}
            value={String(services)}
            to={`/discovery/${latest.id}`}
          />
          <MiniStat
            label={
              d
                ? `Zmiany od poprzedniego (nowe ${d.new_hosts}, znikające ${d.gone_hosts})`
                : "Zmiany: potrzebne dwa przebiegi"
            }
            value={
              d
                ? String(
                    (d.new_hosts ?? 0) +
                      (d.gone_hosts ?? 0) +
                      (d.changed_hosts ?? 0),
                  )
                : "0"
            }
            to="/discovery/porownanie"
          />
          <MiniStat
            label={`Hosty: ${unstableLabel.toLowerCase()}`}
            value={String(states.data?.counts.unstable ?? 0)}
            to="/discovery/porownanie"
          />
        </div>
      ) : (
        <p className="text-sm text-muted-foreground" data-demo="kpis">
          Nie było jeszcze przebiegu discovery.{" "}
          <Link className="text-primary underline" to="/discovery">
            Uruchom pierwszy
          </Link>
          .
        </p>
      )}

      <div className="mt-4 grid gap-6 xl:grid-cols-[2fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Ostatnie przebiegi discovery</CardTitle>
            <CardDescription>
              Czas trwania, postęp i prognoza zakończenia.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {runs.data && runs.data.length > 0 ? (
              <RunsTable runs={runs.data.slice(0, 5)} compact />
            ) : (
              <p className="text-sm text-muted-foreground">
                Nie było jeszcze żadnego przebiegu.
              </p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Wymaga uwagi</CardTitle>
            <CardDescription>
              Panele, staging, hosty niestabilne i eksport do DefectDojo.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            {panels.length + staging.length + unstable.length === 0 && (
              <p className="text-muted-foreground">Nic nie wymaga uwagi.</p>
            )}
            <ul className="space-y-2">
              {[...panels, ...staging]
                .filter(
                  (h, i, all) => all.findIndex((x) => x.ip === h.ip) === i,
                )
                .slice(0, 6)
                .map((h) => (
                  <li key={h.ip} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono">{h.ip}</span>
                    {h.flags
                      .filter((f) => f.kind === "panel" || f.kind === "staging")
                      .map((f) => (
                        <Badge
                          key={f.kind}
                          variant={f.kind === "panel" ? "danger" : "warn"}
                        >
                          {f.label}
                        </Badge>
                      ))}
                  </li>
                ))}
              {unstable.slice(0, 4).map(([ip]) => (
                <li key={`u${ip}`} className="flex items-center gap-2">
                  <span className="font-mono">{ip}</span>
                  <Badge variant="warn">{unstableLabel}</Badge>
                </li>
              ))}
            </ul>
            <div
              className="border-t border-border pt-3"
              data-demo="dojo-status"
            >
              <Badge variant={dojo.data?.ok ? "ok" : "warn"}>
                DefectDojo:{" "}
                {dojo.data
                  ? dojo.data.ok
                    ? dojo.data.detail || "połączono"
                    : dojo.data.detail
                  : "sprawdzanie"}
              </Badge>
              {dojo.data && (
                <p className="mt-1 text-muted-foreground">
                  Wysłane obserwacje: {dojo.data.exported}
                  {dojo.data.last_export
                    ? `, ostatnio ${formatDateTime(dojo.data.last_export)}`
                    : ""}
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

const RUN_STATUS: Record<
  string,
  { label: string; variant: "ok" | "info" | "warn" | "danger" | "neutral" }
> = {
  done: { label: "zakończony", variant: "ok" },
  completed: { label: "zakończony", variant: "ok" },
  running: { label: "w toku", variant: "info" },
  in_progress: { label: "w toku", variant: "info" },
  queued: { label: "w kolejce", variant: "neutral" },
  planned: { label: "zaplanowany", variant: "neutral" },
  awaiting_approval: { label: "czeka na zgodę", variant: "warn" },
  stopped: { label: "zatrzymany", variant: "warn" },
  failed: { label: "błąd", variant: "danger" },
};

function duration(seconds: number | null): string {
  if (seconds === null) return "w toku";
  if (seconds < 60) return `${Math.round(seconds)} s`;
  return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
}

export function Dashboard() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const stats = useQuery({
    queryKey: ["stats"],
    queryFn: api.stats,
    refetchInterval: 15_000,
  });
  const findings = useQuery({
    queryKey: ["findings", "active"],
    queryFn: () => api.findings("active"),
  });
  const notifications = useQuery({
    queryKey: ["notifications"],
    queryFn: api.notifications,
  });
  const chain = useQuery({
    queryKey: ["audit-chain"],
    queryFn: api.auditChain,
  });
  const scope = useQuery({ queryKey: ["scope"], queryFn: api.scope });
  const sprint = useQuery({
    queryKey: ["sprint-dashboard"],
    queryFn: api.sprintDashboard,
    refetchInterval: 15_000,
  });

  const s = stats.data;
  const scopeSize = scope.data
    ? (scope.data.allowed_cidrs?.length ?? 0) +
      (scope.data.allowed_domains?.length ?? 0)
    : undefined;
  const decisions = s ? s.review_queue + s.awaiting_approval : undefined;
  const inApp = notifications.data?.filter((n) => n.channel === "in_app") ?? [];
  const recentRuns = sprint.data?.recent_runs ?? [];

  return (
    <>
      <PageHeader
        title="Pulpit"
        description="Kluczowe wskaźniki bezpieczeństwa, najważniejsze zagrożenia, aktywność i stan discovery."
      />

      <section
        aria-label="Kluczowe wskaźniki"
        className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4"
      >
        <Stat
          label="Aktywne zagrożenia"
          value={s ? String(s.findings_active) : "…"}
          hint={
            s
              ? `Krytyczne: ${s.findings_by_level.krytyczny ?? 0}, wysokie: ${s.findings_by_level.wysoki ?? 0}`
              : "Wczytywanie…"
          }
          to="/zagrozenia"
          tone={
            s && (s.findings_by_level.krytyczny ?? 0) > 0 ? "danger" : "primary"
          }
        />
        <Stat
          label="Katalog CISA KEV"
          value={s ? String(s.kev_active) : "…"}
          hint="Podatności aktywnie wykorzystywane w internecie, na naszych zasobach"
          to="/zagrozenia"
          tone={s && s.kev_active > 0 ? "danger" : "primary"}
          badge={s && s.kev_active > 0 ? <KevBadge /> : undefined}
        />
        <Stat
          label="Zasoby w inwentarzu"
          value={s ? String(s.assets_total) : "…"}
          hint={
            s
              ? `Shadow IT: ${s.assets_by_status.shadow ?? 0}, nie odpowiada: ${s.assets_by_status.missing ?? 0}`
              : "Wczytywanie…"
          }
          to="/zasoby"
        />
        <Stat
          label="Wymaga decyzji / akcji"
          value={decisions === undefined ? "…" : String(decisions)}
          hint={
            s
              ? `Kolejka dopasowań: ${s.review_queue}, skany czekające na zgodę: ${s.awaiting_approval}`
              : "Wczytywanie…"
          }
          to="/weryfikacja"
          tone={decisions ? "warn" : "primary"}
        />
      </section>

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Najważniejsze zagrożenia</CardTitle>
            <CardDescription>
              Kolejność według oceny ryzyka liczonej jawną formułą.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {findings.data && findings.data.items.length === 0 && (
              <p className="text-sm text-muted-foreground">
                Brak aktywnych zagrożeń. Uruchom skan albo wczytaj feedy.
              </p>
            )}
            <ul className="divide-y divide-border">
              {findings.data?.items.slice(0, 6).map((f) => (
                <li key={f.id} className="py-2 text-sm first:pt-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <RiskBadge level={f.risk_level} score={f.risk_score} />
                    <Link
                      className="font-medium text-primary underline"
                      to="/zagrozenia"
                    >
                      {f.vulnerability?.cve_id ?? f.type}
                    </Link>
                    <span className="text-muted-foreground">na</span>
                    <Link className="font-mono" to={`/zasoby/${f.asset.id}`}>
                      {f.asset.name}
                    </Link>
                    {f.vulnerability?.in_kev && <KevBadge />}
                  </div>
                  <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">
                    {f.summary}
                  </p>
                </li>
              ))}
            </ul>
            {s && s.findings_active > 0 && (
              <div className="mt-4 flex flex-wrap gap-2 border-t border-border pt-3">
                {LEVELS.map((level) => (
                  <span key={level} className="flex items-center gap-1 text-xs">
                    <RiskBadge level={level} />
                    <span className="tabular-nums">
                      {s.findings_by_level[level] ?? 0}
                    </span>
                  </span>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Ostatnie powiadomienia i aktywność</CardTitle>
            <CardDescription>
              Jedno powiadomienie na zasób i regułę, bez powtórek w ciągu doby.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {inApp.length === 0 && (
              <p className="text-sm text-muted-foreground">Brak powiadomień.</p>
            )}
            <ul className="divide-y divide-border">
              {inApp.slice(0, 5).map((n) => (
                <li key={n.id} className="py-2 text-sm first:pt-0">
                  <p className="font-medium">{n.payload.title}</p>
                  <p className="text-xs text-muted-foreground">
                    {formatDateTime(n.created_at)} · reguła {n.rule_name} ·{" "}
                    {n.status === "digest_pending"
                      ? "w zestawieniu zbiorczym"
                      : "natychmiast"}
                  </p>
                </li>
              ))}
            </ul>
            {recentRuns.length > 0 && (
              <div className="border-t border-border pt-3">
                <p className="mb-2 text-xs font-semibold uppercase text-muted-foreground">
                  Ostatnie skany
                </p>
                <Table>
                  <thead>
                    <tr>
                      <Th>Start</Th>
                      <Th>Stan</Th>
                      <Th>Czas trwania</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentRuns.map((run) => {
                      const status = RUN_STATUS[run.status] ?? {
                        label: run.status,
                        variant: "neutral" as const,
                      };
                      return (
                        <tr key={run.id}>
                          <Td>
                            <Link
                              className="text-primary underline"
                              to="/skany"
                            >
                              {formatDateTime(run.started_at)}
                            </Link>
                          </Td>
                          <Td>
                            <Badge variant={status.variant}>
                              {status.label}
                            </Badge>
                          </Td>
                          <Td className="tabular-nums">
                            {duration(run.duration_seconds)}
                            {run.duration_seconds === null &&
                            run.eta_seconds !== null
                              ? ` (ETA ${duration(run.eta_seconds)})`
                              : ""}
                          </Td>
                        </tr>
                      );
                    })}
                  </tbody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <DiscoveryOverview />

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Stan systemu</CardTitle>
          <CardDescription>
            {s?.last_scan
              ? `Ostatni skan: ${formatDateTime(s.last_scan.started_at)}.`
              : "Nie było jeszcze żadnego skanu."}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Pill ok={health.data?.database}>
            Baza danych: {health.data?.database ? "działa" : "niedostępna"}
          </Pill>
          <Pill ok={health.data?.redis}>
            Redis (kolejka zadań):{" "}
            {health.data?.redis ? "działa" : "niedostępny"}
          </Pill>
          <Pill ok={chain.data ? chain.data.ok : undefined}>
            Dziennik audytu:{" "}
            {typeof chain.data?.entries === "number"
              ? `${chain.data.entries} wpisów`
              : "sprawdzanie"}
            {chain.data?.ok === false
              ? ", łańcuch NIESPÓJNY"
              : ", łańcuch spójny"}
          </Pill>
          <Pill ok={scopeSize ? true : scope.data ? false : undefined}>
            {scopeSize
              ? `Zakres skanowania: ${scopeSize} ${scopeSize === 1 ? "reguła" : "reguły"}`
              : "Zakres pusty: nic nie jest skanowane"}
          </Pill>
          {s?.feeds.map((f) => (
            <Pill key={f.feed} ok={f.status === "ok"}>
              Feed {f.feed.toUpperCase()}:{" "}
              {f.status === "ok"
                ? f.mode === "offline"
                  ? "snapshot offline"
                  : "online"
                : "brak"}
            </Pill>
          ))}
        </CardContent>
      </Card>
    </>
  );
}

/** Pigułka stanu: zielona kropka działa, czerwona nie działa, szara w trakcie sprawdzania. */
function Pill({
  ok,
  children,
}: {
  ok: boolean | undefined;
  children: ReactNode;
}) {
  const dot =
    ok === undefined
      ? "bg-muted-foreground"
      : ok
        ? "bg-green-500"
        : "bg-red-500";
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-border bg-muted px-3 py-1 text-xs">
      <span className={`size-2 rounded-full ${dot}`} aria-hidden />
      {children}
    </span>
  );
}
