import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { PageHeader, QueryState } from "@/components/Layout";
import { OperatorField } from "@/components/OperatorField";
import { KevBadge, RiskBadge, RiskBar } from "@/components/risk";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { Table, Td, Th } from "@/components/ui/table";
import { api, type FindingDetail, type FindingStatus } from "@/lib/api";
import { STATUS_LABELS } from "@/lib/labels";
import { useOperator } from "@/lib/operator";
import { cn, formatDate, formatDateTime } from "@/lib/utils";

const FILTERS: { value: string; label: string }[] = [
  { value: "active", label: "Aktywne" },
  { value: "resolved", label: "Rozwiązane" },
  { value: "accepted_risk", label: "Ryzyko zaakceptowane" },
  { value: "false_positive", label: "Fałszywe alarmy" },
  { value: "all", label: "Wszystkie" },
];

const EVENT_LABELS: Record<string, string> = {
  created: "Wykryto",
  rescored: "Zmiana oceny ryzyka",
  reopened: "Otwarto ponownie",
  resolved: "Rozwiązano",
  status_changed: "Zmiana statusu",
  assigned: "Zmiana osoby odpowiedzialnej",
};

const NEEDS_REASON: FindingStatus[] = ["accepted_risk", "false_positive"];

function Breakdown({ finding }: { finding: FindingDetail }) {
  const { components, premiums, score } = finding.risk_breakdown;
  return (
    <Table>
      <thead>
        <tr>
          <Th>Składnik</Th>
          <Th>Dane</Th>
          <Th className="text-right">Wartość</Th>
          <Th className="text-right">Waga</Th>
          <Th className="text-right">Punkty</Th>
        </tr>
      </thead>
      <tbody>
        {components.map((c) => (
          <tr key={c.name}>
            <Td className="font-medium">{c.label}</Td>
            <Td className="text-muted-foreground">{c.source}</Td>
            <Td className="text-right tabular-nums">{c.value.toFixed(0)}</Td>
            <Td className="text-right tabular-nums">{(c.weight * 100).toFixed(0)}%</Td>
            <Td className="text-right font-medium tabular-nums">{c.contribution.toFixed(1)}</Td>
          </tr>
        ))}
        {premiums.map((p) => (
          <tr key={p.rule}>
            <Td className="font-medium">Premia: {p.description || p.rule}</Td>
            <Td colSpan={3} />
            <Td className="text-right font-medium tabular-nums">+{p.points.toFixed(1)}</Td>
          </tr>
        ))}
        <tr>
          <Td className="font-semibold" colSpan={4}>
            Ocena ryzyka (0–100)
          </Td>
          <Td className="text-right font-semibold tabular-nums">{score.toFixed(1)}</Td>
        </tr>
      </tbody>
    </Table>
  );
}

function StatusForm({ finding }: { finding: FindingDetail }) {
  const queryClient = useQueryClient();
  const [operator, setOperator] = useOperator();
  const [status, setStatus] = useState<FindingStatus>(finding.status);
  const [reason, setReason] = useState("");
  const update = useMutation({
    mutationFn: () => api.updateFinding(finding.id, { status, reason, actor: operator.trim() }),
    onSuccess: () => {
      setReason("");
      void queryClient.invalidateQueries({ queryKey: ["findings"] });
      void queryClient.invalidateQueries({ queryKey: ["finding", finding.id] });
      void queryClient.invalidateQueries({ queryKey: ["stats"] });
    },
  });
  const needsReason = NEEDS_REASON.includes(status);

  function submit(event: FormEvent) {
    event.preventDefault();
    update.mutate();
  }

  return (
    <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
      <label className="text-xs font-medium">
        Status
        <Select
          className="mt-1 block w-56"
          value={status}
          onChange={(e) => setStatus(e.target.value as FindingStatus)}
        >
          {Object.entries(STATUS_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </Select>
      </label>
      <label className="min-w-56 flex-1 text-xs font-medium">
        Uzasadnienie{needsReason ? " (wymagane)" : " (opcjonalne)"}
        <Input
          className="mt-1"
          required={needsReason}
          minLength={needsReason ? 3 : undefined}
          maxLength={2000}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
      </label>
      <OperatorField value={operator} onChange={setOperator} />
      <Button type="submit" disabled={update.isPending || status === finding.status}>
        Zapisz status
      </Button>
      {update.error && (
        <p className="w-full text-sm text-red-700" role="alert">
          {update.error.message}
        </p>
      )}
    </form>
  );
}

function Detail({ id }: { id: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["finding", id],
    queryFn: () => api.finding(id),
  });
  if (!data) {
    return (
      <Card>
        <QueryState isPending={isPending} error={error} empty={false} emptyText="" />
      </Card>
    );
  }
  const vuln = data.vulnerability;
  const evidence = data.evidence;
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <CardTitle className="text-base">{vuln?.cve_id ?? data.type}</CardTitle>
          <RiskBadge level={data.risk_level} score={data.risk_score} />
          {vuln?.in_kev && <KevBadge />}
          <Badge variant="neutral">{STATUS_LABELS[data.status]}</Badge>
        </div>
        <CardDescription>
          {data.asset.name} · {data.product} {data.version}
          {data.port ? ` · port ${data.port}` : ""}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <section>
          <h3 className="mb-1 text-sm font-semibold">Dlaczego ten poziom</h3>
          <p className="text-sm">{data.summary}</p>
          <div className="mt-3">
            <Breakdown finding={data} />
          </div>
          <p className="mt-2 text-xs text-muted-foreground">
            Ocena liczona jawną formułą (wersja konfiguracji {data.risk_breakdown.config_version},
            plik rules/scoring.yaml). Żaden model językowy nie bierze udziału w ocenie.
          </p>
        </section>

        <section>
          <h3 className="mb-1 text-sm font-semibold">Na jakiej podstawie</h3>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Wykryto</dt>
            <dd className="break-words">{evidence.banner ?? `${data.product} ${data.version}`}</dd>
            <dt className="text-muted-foreground">Podatne wersje</dt>
            <dd>{evidence.affected_range}</dd>
            <dt className="text-muted-foreground">Wersja z poprawką</dt>
            <dd>{data.fixed_version ?? "brak danych w feedzie"}</dd>
            <dt className="text-muted-foreground">Dopasowanie produktu</dt>
            <dd>
              {evidence.cpe} ({evidence.match_method}, pewność{" "}
              {Number(evidence.match_confidence).toFixed(2)})
            </dd>
            {vuln?.kev_due_date && (
              <>
                <dt className="text-muted-foreground">Termin z KEV</dt>
                <dd>{formatDate(vuln.kev_due_date)}</dd>
              </>
            )}
          </dl>
          {data.description && <p className="mt-3 text-sm">{data.description}</p>}
          {data.kev_required_action && (
            <p className="mt-2 text-sm">
              <span className="font-medium">Zalecenie z KEV:</span> {data.kev_required_action}
            </p>
          )}
        </section>

        <section>
          <h3 className="mb-2 text-sm font-semibold">Decyzja</h3>
          <StatusForm key={`${data.id}:${data.status}`} finding={data} />
        </section>

        <section>
          <h3 className="mb-2 text-sm font-semibold">Historia</h3>
          <ul className="space-y-2 text-sm">
            {data.events.map((event) => (
              <li key={event.id} className="border-l-2 border-border pl-3">
                <p>
                  <span className="font-medium">{EVENT_LABELS[event.kind] ?? event.kind}</span>{" "}
                  <span className="text-muted-foreground">
                    · {formatDateTime(event.created_at)} · {event.actor}
                  </span>
                </p>
                {event.reason && <p className="text-muted-foreground">{event.reason}</p>}
              </li>
            ))}
          </ul>
        </section>
      </CardContent>
    </Card>
  );
}

export function Findings() {
  const [filter, setFilter] = useState("active");
  const [selected, setSelected] = useState<string | null>(null);
  const { data, isPending, error } = useQuery({
    queryKey: ["findings", filter],
    queryFn: () => api.findings(filter),
  });
  const current = data?.items.find((f) => f.id === selected) ?? data?.items[0];

  return (
    <>
      <PageHeader
        title="Zagrożenia"
        description="Podatności przypisane do konkretnych zasobów, od najwyższego ryzyka. Wybierz wiersz, żeby zobaczyć, z czego składa się ocena i na jakiej podstawie powstała."
      />
      <div className="mb-4 flex flex-wrap gap-2" role="tablist" aria-label="Filtr statusu">
        {FILTERS.map((item) => (
          <Button
            key={item.value}
            role="tab"
            aria-selected={filter === item.value}
            size="sm"
            variant={filter === item.value ? "default" : "outline"}
            onClick={() => {
              setFilter(item.value);
              setSelected(null);
            }}
          >
            {item.label}
          </Button>
        ))}
      </div>
      <div className="grid items-start gap-6 2xl:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]">
        <Card>
          <QueryState
            isPending={isPending}
            error={error}
            empty={data?.items.length === 0}
            emptyText="Brak zagrożeń w tym widoku. Uruchom skan albo wczytaj feedy."
          />
          {data && data.items.length > 0 && (
            <Table>
              <thead>
                <tr>
                  <Th>Ryzyko</Th>
                  <Th>Podatność</Th>
                  <Th>Zasób</Th>
                  <Th>Oprogramowanie</Th>
                  <Th>Status</Th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((finding) => (
                  <tr
                    key={finding.id}
                    onClick={() => setSelected(finding.id)}
                    className={cn(
                      "cursor-pointer hover:bg-muted",
                      current?.id === finding.id && "bg-muted",
                    )}
                  >
                    <Td className="w-40">
                      <RiskBadge level={finding.risk_level} score={finding.risk_score} />
                      <div className="mt-1.5">
                        <RiskBar level={finding.risk_level} value={finding.risk_score} />
                      </div>
                    </Td>
                    <Td>
                      <button
                        type="button"
                        className="font-medium underline-offset-2 hover:underline"
                        onClick={() => setSelected(finding.id)}
                      >
                        {finding.vulnerability?.cve_id ?? finding.type}
                      </button>
                      {finding.vulnerability?.in_kev && (
                        <span className="ml-2">
                          <KevBadge />
                        </span>
                      )}
                    </Td>
                    <Td>
                      <span className="font-medium">{finding.asset.name}</span>
                      <br />
                      <span className="text-xs text-muted-foreground">
                        {finding.asset.exposure === "internet" ? "internet" : "sieć wewnętrzna"} ·
                        krytyczność {finding.asset.criticality}/5
                      </span>
                    </Td>
                    <Td>
                      {finding.product} {finding.version}
                    </Td>
                    <Td>{STATUS_LABELS[finding.status]}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
        {current && <Detail key={current.id} id={current.id} />}
      </div>
    </>
  );
}
