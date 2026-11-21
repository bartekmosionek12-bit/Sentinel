import { useQuery } from "@tanstack/react-query";
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
import { api, type RiskLevel } from "@shared/lib/api";
import { formatDateTime } from "@shared/lib/utils";

import { HOST_STATE } from "@/labels";
import { RunsTable } from "@/pages/Discovery";

const LEVELS: RiskLevel[] = ["krytyczny", "wysoki", "średni", "niski"];

function Stat({
  label,
  value,
  hint,
  to,
}: {
  label: string;
  value: string;
  hint: string;
  to?: string;
}) {
  return (
    <Card>
      <CardContent className="pb-0">
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="text-3xl font-semibold tabular-nums">{value}</p>
      </CardContent>
      <CardContent className="pt-1">
        <p className="text-xs text-muted-foreground">{hint}</p>
        {to && (
          <Link className="mt-2 inline-block text-xs text-primary underline" to={to}>
            Otwórz
          </Link>
        )}
      </CardContent>
    </Card>
  );
}

function BigNumber({
  label,
  value,
  hint,
  to,
  demo,
}: {
  label: string;
  value: string;
  hint: string;
  to: string;
  demo?: string;
}) {
  return (
    <Link
      to={to}
      className="block border border-border bg-card px-3 py-2.5 text-center hover:border-primary"
      data-demo={demo}
    >
      <p className="text-left text-sm font-semibold">{label}</p>
      <p className="mt-2 text-5xl font-bold text-primary tabular-nums">{value}</p>
      <p className="mt-2 text-xs text-muted-foreground">{hint}</p>
    </Link>
  );
}

/** Discovery na górze pulpitu: najważniejsze liczby, zmiany od ostatniego skanu, ostatnie przebiegi. */
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
  const states = useQuery({ queryKey: ["host-states"], queryFn: api.hostStates });
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
    <section className="mb-8" aria-label="Discovery">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4" data-demo="kpis">
        <BigNumber
          label="Aktywne hosty"
          value={latest ? String(latest.hosts_up) : "–"}
          hint={
            latest
              ? `z ${latest.addresses_total.toLocaleString("pl-PL")} adresów w ostatnim przebiegu`
              : "Uruchom pierwszy przebieg discovery"
          }
          to={latest ? `/discovery/${latest.id}` : "/discovery"}
        />
        <BigNumber
          label="Otwarte usługi"
          value={latest ? String(services) : "–"}
          hint={`Panele administracyjne: ${panels.length}, staging: ${staging.length}`}
          to={latest ? `/discovery/${latest.id}` : "/discovery"}
        />
        <BigNumber
          label="Zmiany od ostatniego skanu"
          value={
            d ? String((d.new_hosts ?? 0) + (d.gone_hosts ?? 0) + (d.changed_hosts ?? 0)) : "–"
          }
          hint={
            d
              ? `Nowe hosty: ${d.new_hosts}, znikające: ${d.gone_hosts}, zmienione: ${d.changed_hosts}`
              : "Potrzebne są dwa przebiegi"
          }
          to="/discovery/porownanie"
        />
        <BigNumber
          label={`Hosty: ${unstableLabel.toLowerCase()}`}
          value={states.data ? String(states.data.counts.unstable ?? 0) : "–"}
          hint={`Nieaktywne: ${states.data?.counts.inactive ?? 0}, niepotwierdzone: ${states.data?.counts.unconfirmed ?? 0}`}
          to="/discovery/porownanie"
        />
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-[2fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Ostatnie przebiegi discovery</CardTitle>
            <CardDescription>Czas trwania, postęp i prognoza zakończenia.</CardDescription>
          </CardHeader>
          <CardContent>
            {runs.data && runs.data.length > 0 ? (
              <RunsTable runs={runs.data.slice(0, 5)} compact />
            ) : (
              <p className="text-sm text-muted-foreground">Nie było jeszcze żadnego przebiegu.</p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Wymaga uwagi</CardTitle>
            <CardDescription>Nowe panele, staging i hosty niestabilne.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <ul className="space-y-2">
              {[...panels, ...staging]
                .filter((h, i, all) => all.findIndex((x) => x.ip === h.ip) === i)
                .slice(0, 6)
                .map((h) => (
                  <li key={h.ip} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono">{h.ip}</span>
                    {h.flags
                      .filter((f) => f.kind === "panel" || f.kind === "staging")
                      .map((f) => (
                        <Badge key={f.kind} variant={f.kind === "panel" ? "danger" : "warn"}>
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
            <div className="border-t border-border pt-3" data-demo="dojo-status">
              <Badge variant={dojo.data?.ok ? "ok" : "warn"}>
                DefectDojo:{" "}
                {dojo.data ? (dojo.data.ok ? "połączono" : dojo.data.detail) : "sprawdzanie"}
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
  const sprint = useQuery({queryKey: ["sprint-dashboard"], queryFn: api.sprintDashboard, refetchInterval: 15_000});

  const s = stats.data;
  const scopeSize = scope.data
    ? scope.data.allowed_cidrs.length + scope.data.allowed_domains.length
    : undefined;
  const decisions = s ? s.review_queue + s.awaiting_approval : undefined;
  const inApp = notifications.data?.filter((n) => n.channel === "in_app") ?? [];

  return (
    <>
      <PageHeader
        title="Pulpit"
        description="Najważniejsze liczby z discovery, zmiany od ostatniego skanu i to, co wymaga uwagi."
      />
      <DiscoveryOverview />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat
          label="Aktywne zagrożenia"
          value={s ? String(s.findings_active) : "–"}
          hint={
            s
              ? `Krytyczne: ${s.findings_by_level.krytyczny ?? 0}, wysokie: ${s.findings_by_level.wysoki ?? 0}`
              : "Wczytywanie…"
          }
          to="/zagrozenia"
        />
        <Stat
          label="Aktywnie wykorzystywane (KEV)"
          value={s ? String(s.kev_active) : "–"}
          hint="Zagrożenia z katalogu CISA KEV na naszych zasobach"
          to="/zagrozenia"
        />
        <Stat
          label="Zasoby w inwentarzu"
          value={s ? String(s.assets_total) : "–"}
          hint={
            s
              ? `Shadow IT: ${s.assets_by_status.shadow ?? 0}, nie odpowiada: ${s.assets_by_status.missing ?? 0}`
              : "Wczytywanie…"
          }
          to="/zasoby"
        />
        <Stat
          label="Czeka na decyzję człowieka"
          value={decisions === undefined ? "–" : String(decisions)}
          hint={
            s
              ? `Dopasowania: ${s.review_queue}, skany inwazyjne: ${s.awaiting_approval}`
              : "Wczytywanie…"
          }
          to={s && s.awaiting_approval > 0 ? "/skany" : "/weryfikacja"}
        />
      </div>

      <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Zmiany od ostatniego skanu" value={String(sprint.data?.change_count ?? "–")} hint="Nowe, znikające i zmienione obserwacje" to="/skany" />
        <Stat label="Panele administracyjne i staging" value={sprint.data ? `${sprint.data.new_admin_panels} / ${sprint.data.staging}` : "–"} hint="Flagi z ostatniego skanu" to="/skany" />
        <Stat label="Hosty niestabilne" value={String(sprint.data?.unstable_hosts ?? "–")} hint="Przeplatane odpowiedzi w ostatnich przebiegach" to="/zasoby" />
        <Stat label="DefectDojo" value={sprint.data?.defectdojo ?? "–"} hint="Lokalny profil Docker Compose" to="/skany" />
      </div>

      <Card className="mt-6"><CardHeader><CardTitle>Ostatnie skany i zmiany</CardTitle></CardHeader><CardContent className="space-y-2 text-sm">
        {sprint.data?.recent_runs.map((run) => <p key={run.id}>{formatDateTime(run.started_at)} · {run.status} · czas {run.duration_seconds ?? "w toku"} s · ETA {run.eta_seconds ?? "?"} s</p>)}
        {sprint.data?.changes.slice(0, 5).map((change, index) => <p key={index}>{change.kind}: {change.host} {change.item}</p>)}
        {sprint.data?.flags.slice(0, 5).map((flag, index) => <p key={index}>{flag.kind}: {flag.host} · dowody {flag.confidence}</p>)}
      </CardContent></Card>

      <div className="mt-6 grid gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Najważniejsze zagrożenia</CardTitle>
            <CardDescription>Kolejność według oceny ryzyka liczonej jawną formułą.</CardDescription>
          </CardHeader>
          <CardContent>
            {findings.data && findings.data.items.length === 0 && (
              <p className="text-sm text-muted-foreground">
                Brak aktywnych zagrożeń. Uruchom skan albo wczytaj feedy.
              </p>
            )}
            <ul className="space-y-3">
              {findings.data?.items.slice(0, 5).map((f) => (
                <li key={f.id} className="text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <RiskBadge level={f.risk_level} score={f.risk_score} />
                    <Link className="font-medium text-primary underline" to="/zagrozenia">
                      {f.vulnerability?.cve_id ?? f.type}
                    </Link>
                    <span>na {f.asset.name}</span>
                    {f.vulnerability?.in_kev && <KevBadge />}
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">{f.summary}</p>
                </li>
              ))}
            </ul>
            {s && s.findings_active > 0 && (
              <div className="mt-4 flex flex-wrap gap-2">
                {LEVELS.map((level) => (
                  <span key={level} className="flex items-center gap-1 text-xs">
                    <RiskBadge level={level} />
                    <span className="tabular-nums">{s.findings_by_level[level] ?? 0}</span>
                  </span>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Ostatnie powiadomienia</CardTitle>
            <CardDescription>
              Jedno powiadomienie na zasób i regułę, bez powtórek w ciągu doby.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {inApp.length === 0 && (
              <p className="text-sm text-muted-foreground">Brak powiadomień.</p>
            )}
            <ul className="space-y-3">
              {inApp.slice(0, 5).map((n) => (
                <li key={n.id} className="text-sm">
                  <p className="font-medium">{n.payload.title}</p>
                  <p className="text-xs text-muted-foreground">
                    {formatDateTime(n.created_at)} · reguła {n.rule_name} ·{" "}
                    {n.status === "digest_pending" ? "w zestawieniu zbiorczym" : "natychmiast"}
                  </p>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>

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
          <Badge variant={health.data?.database ? "ok" : "danger"}>
            Baza danych: {health.data?.database ? "działa" : "niedostępna"}
          </Badge>
          <Badge variant={health.data?.redis ? "ok" : "danger"}>
            Kolejka zadań: {health.data?.redis ? "działa" : "niedostępna"}
          </Badge>
          <Badge variant={scopeSize ? "ok" : "warn"}>
            {scopeSize
              ? `Zakres skanowania: ${scopeSize} ${scopeSize === 1 ? "reguła" : "reguły"}`
              : "Zakres pusty: nic nie jest skanowane"}
          </Badge>
          <Badge variant={chain.data?.ok === false ? "danger" : "ok"}>
            Dziennik audytu: {chain.data ? `${chain.data.entries} wpisów` : "sprawdzanie"}
            {chain.data?.ok === false ? ", łańcuch NIESPÓJNY" : ", łańcuch spójny"}
          </Badge>
          {s?.feeds.map((f) => (
            <Badge key={f.feed} variant={f.status === "ok" ? "ok" : "neutral"}>
              Feed {f.feed.toUpperCase()}:{" "}
              {f.status === "ok" ? (f.mode === "offline" ? "snapshot offline" : "online") : "brak"}
            </Badge>
          ))}
        </CardContent>
      </Card>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Od czego zacząć</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p>
            1. Ustaw{" "}
            <Link className="text-primary underline" to="/zakres">
              zakres skanowania
            </Link>
            . Bez niego system niczego nie dotknie.
          </p>
          <p>
            2. Zaimportuj{" "}
            <Link className="text-primary underline" to="/zasoby">
              zasoby
            </Link>{" "}
            z pliku CSV, a potem uruchom{" "}
            <Link className="text-primary underline" to="/skany">
              skan
            </Link>
            .
          </p>
          <p>
            3. Każdą decyzję systemu znajdziesz w{" "}
            <Link className="text-primary underline" to="/audyt">
              dzienniku audytu
            </Link>
            .
          </p>
        </CardContent>
      </Card>
    </>
  );
}
