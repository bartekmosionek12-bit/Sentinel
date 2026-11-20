import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { PageHeader, QueryState } from "@shared/components/page";
import { RiskBadge } from "@shared/components/risk";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@shared/components/ui/card";
import { api, type RiskLevel } from "@shared/lib/api";
import { formatDateTime } from "@shared/lib/utils";

const LEVELS: RiskLevel[] = ["krytyczny", "wysoki", "średni", "niski"];

function Tile({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <Card>
      <CardHeader>
        <CardDescription>{label}</CardDescription>
        <p className="text-3xl font-semibold tabular-nums">{value}</p>
      </CardHeader>
      <CardContent>
        <p className="text-xs text-muted-foreground">{hint}</p>
      </CardContent>
    </Card>
  );
}

export function Home() {
  const stats = useQuery({ queryKey: ["stats"], queryFn: api.stats });
  const data = stats.data;
  const critical = data?.findings_by_level.krytyczny ?? 0;
  return (
    <>
      <PageHeader
        title="Stan bezpieczeństwa"
        description="Podsumowanie dla menedżera. Szczegóły techniczne i adresy są ukryte; pełny widok ma zespół bezpieczeństwa w konsoli operacyjnej."
      />
      <QueryState
        isPending={stats.isPending}
        error={stats.error}
        empty={false}
        emptyText=""
      />
      {data && (
        <div className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Tile
              label="Zagrożenia krytyczne"
              value={String(critical)}
              hint={critical ? "Wymagają działania w pierwszej kolejności" : "Brak krytycznych"}
            />
            <Tile
              label="Aktywnie wykorzystywane (KEV)"
              value={String(data.kev_active)}
              hint="Podatności, które według CISA są już używane w atakach"
            />
            <Tile
              label="Wszystkie otwarte zagrożenia"
              value={String(data.findings_active)}
              hint="Otwarte i w trakcie naprawy"
            />
            <Tile
              label="Zasoby w inwentarzu"
              value={String(data.assets_total)}
              hint={`W tym niepotwierdzone: ${data.assets_by_status.shadow ?? 0}`}
            />
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Zagrożenia według poziomu ryzyka</CardTitle>
              <CardDescription>
                Poziom wylicza deterministyczna reguła (CVSS, KEV, EPSS, ekspozycja i ważność
                zasobu), nie model językowy.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-3">
              {LEVELS.map((level) => (
                <span key={level} className="flex items-center gap-2 text-sm">
                  <RiskBadge level={level} />
                  <span className="tabular-nums">{data.findings_by_level[level] ?? 0}</span>
                </span>
              ))}
            </CardContent>
          </Card>
          <p className="text-sm text-muted-foreground">
            {data.last_scan
              ? `Ostatni skan: ${formatDateTime(data.last_scan.started_at)}.`
              : "Nie było jeszcze skanu."}{" "}
            <Link className="underline" to="/zagrozenia">
              Zobacz najważniejsze zagrożenia
            </Link>
          </p>
        </div>
      )}
    </>
  );
}
