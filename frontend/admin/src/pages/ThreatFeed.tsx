import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { PageHeader, QueryState } from "@/components/Layout";
import { KevBadge, RiskBadge } from "@/components/risk";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { api } from "@/lib/api";
import { formatDate, formatDateTime } from "@/lib/utils";

const FEED_NAMES: Record<string, string> = {
  nvd: "NVD",
  kev: "CISA KEV",
  epss: "EPSS",
};

function Counter({ label, value, hint }: { label: string; value: number; hint: string }) {
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

export function ThreatFeed() {
  const queryClient = useQueryClient();
  const [scope, setScope] = useState<"ours" | "all">("ours");
  const feed = useQuery({
    queryKey: ["threat-feed", scope],
    queryFn: () => api.threatFeed(scope),
  });
  const stats = useQuery({ queryKey: ["stats"], queryFn: api.stats });
  const sync = useMutation({
    mutationFn: api.syncFeeds,
    onSuccess: () => {
      window.setTimeout(() => void queryClient.invalidateQueries(), 3000);
    },
  });
  const data = feed.data;

  return (
    <>
      <PageHeader
        title="Feed zagrożeń"
        description="Podatności z feedów (NVD, CISA KEV, EPSS). Najpierw te, które dotyczą naszych zasobów, obok wszystkich znanych systemowi."
      />
      <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Counter
          label="Nowe dziś, które nas dotyczą"
          value={data?.new_ours ?? 0}
          hint="Mają aktywne zagrożenie na co najmniej jednym zasobie"
        />
        <Counter
          label="Nowe dziś ogółem"
          value={data?.new_total ?? 0}
          hint="Wczytane od północy (UTC)"
        />
        <Counter
          label="Dotyczą nas łącznie"
          value={data?.total_ours ?? 0}
          hint="Podatności z aktywnym zagrożeniem"
        />
        <Counter
          label="Znane podatności"
          value={data?.total ?? 0}
          hint="Wszystkie wczytane z feedów"
        />
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="flex gap-2" role="tablist" aria-label="Zakres feedu">
          <Button
            role="tab"
            aria-selected={scope === "ours"}
            size="sm"
            variant={scope === "ours" ? "default" : "outline"}
            onClick={() => setScope("ours")}
          >
            Które nas dotyczą
          </Button>
          <Button
            role="tab"
            aria-selected={scope === "all"}
            size="sm"
            variant={scope === "all" ? "default" : "outline"}
            onClick={() => setScope("all")}
          >
            Wszystkie
          </Button>
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          {stats.data?.feeds.map((f) => (
            <Badge
              key={f.feed}
              variant={f.status === "ok" ? "ok" : f.status === "never" ? "neutral" : "danger"}
              title={f.error ?? (f.finished_at ? formatDateTime(f.finished_at) : "")}
            >
              {FEED_NAMES[f.feed] ?? f.feed}:{" "}
              {f.status === "ok"
                ? `${f.mode === "offline" ? "snapshot offline" : "online"}`
                : f.status === "never"
                  ? "nie wczytano"
                  : "błąd"}
            </Badge>
          ))}
          <Button
            size="sm"
            variant="outline"
            disabled={sync.isPending}
            onClick={() => sync.mutate()}
          >
            Wczytaj feedy
          </Button>
        </div>
      </div>
      {sync.error && (
        <p className="mb-3 text-sm text-red-700" role="alert">
          {sync.error.message}
        </p>
      )}

      <Card>
        <QueryState
          isPending={feed.isPending}
          error={feed.error}
          empty={data?.items.length === 0}
          emptyText={
            scope === "ours"
              ? "Żadna znana podatność nie dotyczy teraz naszych zasobów."
              : "Feedy nie zostały jeszcze wczytane."
          }
        />
        {data && data.items.length > 0 && (
          <Table>
            <thead>
              <tr>
                <Th>Podatność</Th>
                <Th>Opis</Th>
                <Th className="text-right">CVSS</Th>
                <Th className="text-right">EPSS</Th>
                <Th>Opublikowano</Th>
                <Th>Nasze zasoby</Th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((threat) => (
                <tr key={threat.cve_id}>
                  <Td className="whitespace-nowrap">
                    <span className="font-medium">{threat.cve_id}</span>
                    <div className="mt-1 flex gap-1">
                      {threat.in_kev && <KevBadge />}
                      {threat.is_new && <Badge variant="info">nowe dziś</Badge>}
                    </div>
                  </Td>
                  <Td className="max-w-md text-muted-foreground">{threat.description}</Td>
                  <Td className="text-right tabular-nums">
                    {threat.cvss_score?.toFixed(1) ?? "brak"}
                  </Td>
                  <Td className="text-right tabular-nums">
                    {threat.epss === null ? "brak" : `${(threat.epss * 100).toFixed(0)}%`}
                  </Td>
                  <Td className="whitespace-nowrap">
                    {threat.published ? formatDate(threat.published) : "brak"}
                  </Td>
                  <Td>
                    {threat.affected_assets.length === 0 ? (
                      <span className="text-muted-foreground">nie dotyczy</span>
                    ) : (
                      <ul className="space-y-1">
                        {threat.affected_assets.map((a) => (
                          <li key={a.finding_id} className="flex items-center gap-2">
                            <Link className="text-primary underline" to="/zagrozenia">
                              {a.asset_name}
                            </Link>
                            <RiskBadge level={a.risk_level} score={a.risk_score} />
                          </li>
                        ))}
                      </ul>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
