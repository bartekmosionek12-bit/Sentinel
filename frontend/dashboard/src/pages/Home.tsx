import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Camera, HelpCircle } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";

import { CoverageTrend } from "@shared/components/CoverageTrend";
import { FreshnessNote } from "@shared/components/freshness";
import { PageHeader, QueryState } from "@shared/components/page";
import { LightBadge } from "@shared/components/reports";
import { KevBadge, RiskBadge } from "@shared/components/risk";
import { Badge } from "@shared/components/ui/badge";
import { Button } from "@shared/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@shared/components/ui/card";
import { Table, Td, Th } from "@shared/components/ui/table";
import { api, type OrgUnitSummary, type ReportListItem } from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";
import { formatDateTime } from "@shared/lib/utils";

/** Jedno zdanie o stanie: z ostatniego raportu (światło i powód liczy kod, nie model). */
function Headline({ report }: { report: ReportListItem | undefined }) {
  if (!report)
    return (
      <p className="text-lg">Nie ma jeszcze raportu o stanie. Pojawi się po pierwszym skanie.</p>
    );
  return (
    <div className="flex flex-wrap items-center gap-3" data-demo="headline">
      <LightBadge light={report.light} />
      <p className="text-lg font-medium">{report.light_reason}.</p>
      <Link className="text-sm underline" to={`/raporty/${report.id}`}>
        Otwórz raport z {formatDateTime(report.created_at)}
      </Link>
    </div>
  );
}

/** „Aktualny obraz”: raport z bieżącego stanu w kilka sekund, bez skanowania (§25.1). */
function CurrentPicture() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const create = useMutation({
    mutationFn: api.currentReport,
    onSuccess: (report) => {
      void queryClient.invalidateQueries({ queryKey: ["inbox"] });
      navigate(`/raporty/${report.id}`);
    },
  });
  if (!can("reports:snapshot")) return null;
  return (
    <span className="inline-flex items-center gap-2">
      <Button onClick={() => create.mutate()} disabled={create.isPending} data-demo="current-picture">
        <Camera className="size-4" aria-hidden />
        {create.isPending ? "Przygotowuję raport…" : "Aktualny obraz"}
      </Button>
      {create.error && (
        <span role="alert" className="text-sm text-red-700">
          {create.error.message}
        </span>
      )}
    </span>
  );
}

function Tile({
  label,
  value,
  hint,
  to,
  demo,
}: {
  label: string;
  value: string;
  hint: string;
  to?: string;
  demo?: string;
}) {
  const body = (
    <Card className={to ? "h-full transition-colors hover:border-sky-300" : "h-full"} data-demo={demo}>
      <CardHeader>
        <CardDescription>{label}</CardDescription>
        <p className="text-3xl font-semibold tabular-nums">{value}</p>
      </CardHeader>
      <CardContent>
        <p className="text-xs text-muted-foreground">{hint}</p>
      </CardContent>
    </Card>
  );
  return to ? <Link to={to}>{body}</Link> : body;
}

/** Działy najwyższego poziomu z sumą poddziałów. */
function rollup(units: OrgUnitSummary[]): (OrgUnitSummary & { children: string[] })[] {
  const order = ["krytyczny", "wysoki", "średni", "niski"];
  return units
    .filter((u) => u.parent_id === null)
    .map((root) => {
      const kids = units.filter((u) => u.parent_id === root.id);
      const all = [root, ...kids];
      const levels = all.map((u) => u.worst_level).filter(Boolean) as string[];
      return {
        ...root,
        devices: all.reduce((n, u) => n + u.devices, 0),
        unknown: all.reduce((n, u) => n + u.unknown, 0),
        open_findings: all.reduce((n, u) => n + u.open_findings, 0),
        critical: all.reduce((n, u) => n + u.critical, 0),
        worst_level: (order.find((l) => levels.includes(l)) ?? null) as OrgUnitSummary["worst_level"],
        children: kids.map((k) => k.name),
      };
    })
    .sort((a, b) => b.critical - a.critical || b.open_findings - a.open_findings);
}

export function Home() {
  // Odświeżanie jak skrzynka (co 5 s), żeby zero-day i nowe skany pojawiały się same.
  const overview = useQuery({
    queryKey: ["org-overview"],
    queryFn: api.orgOverview,
    refetchInterval: 5_000,
  });
  const stats = useQuery({ queryKey: ["stats"], queryFn: api.stats, refetchInterval: 5_000 });
  const inbox = useQuery({ queryKey: ["inbox"], queryFn: api.inbox, refetchInterval: 5_000 });
  const findings = useQuery({
    queryKey: ["findings", "active"],
    queryFn: () => api.findings("active"),
  });
  const org = overview.data;
  const latest = inbox.data?.items.find((r) => r.kind === "assessment" || r.kind === "zero_day");
  const top = (findings.data?.items ?? []).slice(0, 5);
  const coverage = org?.coverage;
  return (
    <>
      <PageHeader
        title="Stan bezpieczeństwa"
        description="Podsumowanie dla menedżera. Szczegóły techniczne i adresy są ukryte; pełny widok ma zespół bezpieczeństwa w konsoli operacyjnej."
      />
      <QueryState
        isPending={overview.isPending}
        error={overview.error}
        empty={false}
        emptyText=""
      />
      {org && coverage && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <Headline report={latest} />
            <CurrentPicture />
          </div>
          <FreshnessNote />
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Tile
              label="Zagrożenia krytyczne"
              value={String(coverage.critical_findings)}
              hint={
                coverage.critical_findings
                  ? "Wymagają działania w pierwszej kolejności"
                  : "Brak krytycznych"
              }
              to="/zagrozenia"
              demo="tile-critical"
            />
            <Tile
              label="Aktywnie wykorzystywane (KEV)"
              value={String(stats.data?.kev_active ?? "–")}
              hint="Podatności, które według CISA są już używane w atakach"
              to="/zagrozenia"
            />
            <Tile
              label="Urządzenia w organizacji"
              value={String(coverage.assets_total)}
              hint={`${coverage.with_owner_pct.toFixed(0)}% ma właściciela (osobę albo dział)`}
              to="/urzadzenia"
              demo="tile-devices"
            />
            <Tile
              label="Nieznane urządzenia"
              value={String(coverage.unknown_devices)}
              hint="Widziane w sieci, a nie ma ich w CMDB, AD ani MDM (możliwe shadow IT)"
              to="/nieznane"
              demo="tile-unknown"
            />
          </div>

          <div className="grid gap-6 xl:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Najważniejsze zagrożenia</CardTitle>
                <CardDescription>Pięć otwartych zagrożeń o najwyższym ryzyku.</CardDescription>
              </CardHeader>
              <CardContent>
                {top.length === 0 ? (
                  <p className="text-sm text-muted-foreground">Brak otwartych zagrożeń.</p>
                ) : (
                  <ol className="space-y-3">
                    {top.map((finding) => (
                      <li key={finding.id} className="flex items-start gap-3">
                        <RiskBadge level={finding.risk_level} score={finding.risk_score} />
                        <span className="min-w-0 text-sm">
                          <span className="flex items-center gap-2 font-medium">
                            {finding.asset.name}:{" "}
                            {finding.vulnerability?.cve_id ??
                              (finding.type === "exposure" ? "nieznane urządzenie" : finding.type)}
                            {finding.vulnerability?.in_kev && <KevBadge />}
                          </span>
                          <span className="block text-xs text-muted-foreground">
                            {finding.summary}
                          </span>
                        </span>
                      </li>
                    ))}
                  </ol>
                )}
                <Link className="mt-4 inline-block text-sm underline" to="/zagrozenia">
                  Wszystkie zagrożenia
                </Link>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Pokrycie inwentarza</CardTitle>
                <CardDescription>
                  Ile wiemy o własnych urządzeniach. Dziś: {coverage.with_owner_pct.toFixed(0)}%
                  z właścicielem, {coverage.scanned_recently_pct.toFixed(0)}% skanowanych w
                  ostatnich 7 dniach, {coverage.known_version_pct.toFixed(0)}% ze znaną wersją
                  oprogramowania.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CoverageTrend trend={org.trend} />
              </CardContent>
            </Card>
          </div>

          <Card data-demo="units">
            <CardHeader>
              <CardTitle>Działy</CardTitle>
              <CardDescription>
                Gdzie są urządzenia i zagrożenia. Kliknij dział, żeby zobaczyć jego urządzenia.
              </CardDescription>
            </CardHeader>
            <Table>
              <thead>
                <tr>
                  <Th>Dział</Th>
                  <Th>Urządzenia</Th>
                  <Th>Nieznane</Th>
                  <Th>Otwarte zagrożenia</Th>
                  <Th>Najwyższe ryzyko</Th>
                </tr>
              </thead>
              <tbody>
                {rollup(org.units).map((unit) => (
                  <tr key={unit.id}>
                    <Td>
                      <Link className="font-medium underline-offset-2 hover:underline" to={`/urzadzenia?dzial=${unit.id}`}>
                        {unit.name}
                      </Link>
                      {unit.children.length > 0 && (
                        <span className="block text-xs text-muted-foreground">
                          {unit.children.join(", ")}
                        </span>
                      )}
                    </Td>
                    <Td className="tabular-nums">{unit.devices}</Td>
                    <Td>
                      {unit.unknown ? (
                        <Badge variant="warn">
                          <HelpCircle className="mr-1 size-3" aria-hidden />
                          {unit.unknown}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">0</span>
                      )}
                    </Td>
                    <Td className="tabular-nums">{unit.open_findings}</Td>
                    <Td>
                      {unit.worst_level ? (
                        <RiskBadge level={unit.worst_level} />
                      ) : (
                        <span className="text-muted-foreground">brak</span>
                      )}
                    </Td>
                  </tr>
                ))}
                {org.unassigned_devices > 0 && (
                  <tr>
                    <Td>
                      <Link className="font-medium underline-offset-2 hover:underline" to="/nieznane">
                        Bez działu
                      </Link>
                      <span className="block text-xs text-muted-foreground">
                        Urządzenia, których żaden dział nie zgłosił
                      </span>
                    </Td>
                    <Td className="tabular-nums">{org.unassigned_devices}</Td>
                    <Td>
                      <Badge variant="warn">
                        <HelpCircle className="mr-1 size-3" aria-hidden />
                        {coverage.unknown_devices}
                      </Badge>
                    </Td>
                    <Td className="text-muted-foreground">na liście nieznanych</Td>
                    <Td />
                  </tr>
                )}
              </tbody>
            </Table>
          </Card>
          {org.demo_label && (
            <p className="text-xs text-muted-foreground">
              Osoby i organizacja są fikcyjne ({org.demo_label}).
            </p>
          )}
        </div>
      )}
    </>
  );
}
