import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { PageHeader, QueryState } from "@shared/components/page";
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
import { api, type DictDiff, type DiscoveryRun } from "@shared/lib/api";
import { formatDateTime } from "@shared/lib/utils";

import { HOST_STATE } from "@/labels";

function RunSelect({
  label,
  runs,
  value,
  onChange,
}: {
  label: string;
  runs: DiscoveryRun[];
  value: string;
  onChange: (id: string) => void;
}) {
  return (
    <label className="text-sm font-medium">
      {label}
      <select
        data-demo={`select-${label === "Starszy przebieg" ? "older" : "newer"}`}
        className="mt-1 block h-10 w-full rounded-md border border-border bg-background px-3 text-sm"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        {runs.map((run) => (
          <option key={run.id} value={run.id}>
            {run.name || "Bez nazwy"} · {formatDateTime(run.created_at)} · {run.hosts_up} hostów
          </option>
        ))}
      </select>
    </label>
  );
}

function DiffLines({ diff, label }: { diff?: DictDiff; label: string }) {
  if (!diff) return null;
  return (
    <>
      {Object.entries(diff.added).map(([k, v]) => (
        <li key={`+${label}${k}`}>
          <Badge variant="ok">nowy {label}</Badge> <span className="font-mono">{k}</span> {v}
        </li>
      ))}
      {Object.entries(diff.removed).map(([k, v]) => (
        <li key={`-${label}${k}`}>
          <Badge variant="danger">zniknął {label}</Badge> <span className="font-mono">{k}</span> {v}
        </li>
      ))}
      {Object.entries(diff.changed).map(([k, [a, b]]) => (
        <li key={`~${label}${k}`}>
          <Badge variant="warn">zmieniony {label}</Badge> <span className="font-mono">{k}</span>:{" "}
          <span className="line-through opacity-70">{a || "–"}</span> → {b || "–"}
        </li>
      ))}
    </>
  );
}

export function DiscoveryCompare() {
  const runs = useQuery({
    queryKey: ["discovery-runs"],
    queryFn: api.discoveryRuns,
  });
  const states = useQuery({
    queryKey: ["host-states"],
    queryFn: api.hostStates,
  });
  const done = (runs.data ?? []).filter((r) => r.status === "done" || r.status === "stopped");
  const [params] = useSearchParams();
  const [older, setOlder] = useState(params.get("older") ?? "");
  const [newer, setNewer] = useState(params.get("newer") ?? "");
  useEffect(() => {
    const [latest, previous] = done;
    if (latest && previous && !older && !newer) {
      setNewer(latest.id);
      setOlder(previous.id);
    }
  }, [done, older, newer]);
  const diff = useQuery({
    queryKey: ["compare", older, newer],
    queryFn: () => api.compareRuns(older, newer),
    enabled: Boolean(older && newer && older !== newer),
  });
  const d = diff.data;

  return (
    <>
      <PageHeader
        title="Porównanie przebiegów"
        description="Co się zmieniło między dowolnymi dwoma przebiegami: nowe, znikające i zmienione hosty, usługi, technologie, nagłówki i tytuły stron."
      />
      <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4" data-demo="states">
        {Object.entries(HOST_STATE).map(([key, item]) => (
          <Card key={key}>
            <CardHeader>
              <Badge variant={item.variant} className="w-fit">
                {item.label}
              </Badge>
              <p className="text-4xl font-bold tabular-nums">{states.data?.counts[key] ?? 0}</p>
              <CardDescription>{item.hint}</CardDescription>
            </CardHeader>
          </Card>
        ))}
      </div>

      <Card className="mb-6">
        <CardContent className="grid gap-4 pt-5 md:grid-cols-[1fr_1fr_auto]">
          <RunSelect label="Starszy przebieg" runs={done} value={older} onChange={setOlder} />
          <RunSelect label="Nowszy przebieg" runs={done} value={newer} onChange={setNewer} />
          <div className="flex items-end gap-2">
            <Button
              variant="outline"
              disabled={!d}
              onClick={() => void api.exportDiff(older, newer, "csv")}
            >
              <Download className="size-4" aria-hidden />
              CSV
            </Button>
            <Button
              variant="outline"
              disabled={!d}
              onClick={() => void api.exportDiff(older, newer, "json")}
            >
              <Download className="size-4" aria-hidden />
              JSON
            </Button>
          </div>
        </CardContent>
      </Card>
      {done.length < 2 && (
        <p className="text-sm text-muted-foreground">
          Do porównania potrzebne są dwa zakończone przebiegi.
        </p>
      )}
      <QueryState isPending={diff.isLoading} error={diff.error} empty={false} emptyText="" />

      {d && (
        <>
          <div className="mb-6 grid gap-4 sm:grid-cols-3 xl:grid-cols-5" data-demo="diff-counts">
            {[
              ["Nowe hosty", d.counts.new_hosts, "ok"],
              ["Znikające hosty", d.counts.gone_hosts, "danger"],
              ["Zmienione hosty", d.counts.changed_hosts, "warn"],
              ["Nowe usługi", d.counts.new_services, "ok"],
              ["Znikające usługi", d.counts.gone_services, "danger"],
            ].map(([label, value, variant]) => (
              <Card key={String(label)}>
                <CardHeader>
                  <Badge variant={variant as "ok" | "warn" | "danger"} className="w-fit">
                    {label}
                  </Badge>
                  <p className="text-4xl font-bold tabular-nums">{value}</p>
                </CardHeader>
              </Card>
            ))}
          </div>

          <Card data-demo="diff">
            <CardHeader>
              <CardTitle className="text-lg">Szczegóły zmian</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <thead>
                  <tr>
                    <Th>Host</Th>
                    <Th>Stan</Th>
                    <Th>Zmiana</Th>
                  </tr>
                </thead>
                <tbody>
                  {d.new_hosts.map((h) => (
                    <tr key={`n${h.ip}`}>
                      <Td className="font-mono">{h.ip}</Td>
                      <Td>
                        <StateOf ip={h.ip} states={states.data?.hosts} />
                      </Td>
                      <Td>
                        <Badge variant="ok">Nowy host</Badge>{" "}
                        <span className="font-mono text-xs">{h.services.join(", ")}</span>
                      </Td>
                    </tr>
                  ))}
                  {d.gone_hosts.map((h) => (
                    <tr key={`g${h.ip}`}>
                      <Td className="font-mono">{h.ip}</Td>
                      <Td>
                        <StateOf ip={h.ip} states={states.data?.hosts} />
                      </Td>
                      <Td>
                        <Badge variant="danger">Host zniknął</Badge>{" "}
                        <span className="font-mono text-xs">{h.services.join(", ")}</span>
                      </Td>
                    </tr>
                  ))}
                  {d.changed_hosts.map((h) => (
                    <tr key={`c${h.ip}`}>
                      <Td className="font-mono">
                        {h.ip}
                        <p className="font-sans text-xs text-muted-foreground">
                          {h.hostname ?? ""}
                        </p>
                      </Td>
                      <Td>
                        <StateOf ip={h.ip} states={states.data?.hosts} />
                      </Td>
                      <Td>
                        <ul className="space-y-1 text-sm">
                          <DiffLines diff={h.services} label="usługa" />
                          <DiffLines diff={h.headers} label="nagłówek" />
                          <DiffLines diff={h.titles} label="tytuł" />
                          {h.technologies?.added.map((t) => (
                            <li key={`t+${t}`}>
                              <Badge variant="ok">nowa technologia</Badge> {t}
                            </li>
                          ))}
                          {h.technologies?.removed.map((t) => (
                            <li key={`t-${t}`}>
                              <Badge variant="danger">zniknęła technologia</Badge> {t}
                            </li>
                          ))}
                          {h.flags?.added.map((t) => (
                            <li key={`f+${t}`}>
                              <Badge variant="warn">nowa flaga</Badge> {t}
                            </li>
                          ))}
                        </ul>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </CardContent>
          </Card>
        </>
      )}
    </>
  );
}

function StateOf({ ip, states }: { ip: string; states?: Record<string, { state: string }> }) {
  const state = states?.[ip]?.state;
  if (!state) return <span className="text-xs text-muted-foreground">–</span>;
  const item = HOST_STATE[state] ?? {
    label: state,
    variant: "neutral" as const,
  };
  return <Badge variant={item.variant}>{item.label}</Badge>;
}
