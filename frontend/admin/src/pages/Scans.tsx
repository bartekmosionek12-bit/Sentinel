import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { PageHeader, QueryState } from "@shared/components/page";
import { Badge } from "@shared/components/ui/badge";
import { Button } from "@shared/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@shared/components/ui/card";
import { Input } from "@shared/components/ui/input";
import { Table, Td, Th } from "@shared/components/ui/table";
import { RequestStatus } from "@shared/components/freshness";
import { api, type ScanAction, type ScanRequest } from "@shared/lib/api";
import { SignedBy } from "@shared/lib/auth";
import { formatDateTime } from "@shared/lib/utils";

const STATUS: Record<
  string,
  { label: string; variant: "ok" | "warn" | "danger" | "neutral" | "info" }
> = {
  planned: { label: "Zaplanowana", variant: "neutral" },
  running: { label: "W toku", variant: "info" },
  done: { label: "Wykonana", variant: "ok" },
  awaiting_approval: { label: "Czeka na zgodę", variant: "warn" },
  denied: { label: "Zablokowana", variant: "danger" },
  failed: { label: "Błąd narzędzia", variant: "danger" },
};

const LEVELS: Record<number, string> = { 1: "L1 lekka", 2: "L2 inwazyjna", 3: "L3 red team" };
const TRIGGERS: Record<string, string> = {
  manual: "ręcznie",
  scheduled: "harmonogram",
  seed_demo: "seed_demo",
  manager_request: "prośba menedżera",
};

function StatusBadge({ status }: { status: string }) {
  const item = STATUS[status] ?? { label: status, variant: "neutral" as const };
  return <Badge variant={item.variant}>{item.label}</Badge>;
}

function Approvals({ actions }: { actions: ScanAction[] }) {
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const refresh = () => {
    setReason("");
    void queryClient.invalidateQueries();
    window.setTimeout(() => void queryClient.invalidateQueries(), 5000);
  };
  const approve = useMutation({
    mutationFn: (id: string) => api.approveAction(id, reason.trim()),
    onSuccess: refresh,
  });
  const reject = useMutation({
    mutationFn: (id: string) => api.rejectAction(id, reason.trim()),
    onSuccess: refresh,
  });
  const ready = reason.trim().length >= 3;
  const busy = approve.isPending || reject.isPending;
  const failure = approve.error ?? reject.error;

  return (
    <Card className="mb-6 border-amber-300">
      <CardHeader>
        <CardTitle>Czeka na zgodę człowieka ({actions.length})</CardTitle>
        <CardDescription>
          Bardziej inwazyjne skany nie uruchamiają się same. Po zatwierdzeniu akcja i tak przechodzi
          przez kontrolę zakresu.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <SignedBy />
          <label className="min-w-64 flex-1 text-xs font-medium">
            Uzasadnienie decyzji (wymagane)
            <Input
              className="mt-1"
              maxLength={2000}
              placeholder="np. okno serwisowe uzgodnione z właścicielem"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </label>
        </div>
        {failure && (
          <p className="mb-3 text-sm text-red-700" role="alert">
            {failure.message}
          </p>
        )}
        <Table>
          <thead>
            <tr>
              <Th>Cel</Th>
              <Th>Akcja</Th>
              <Th>Reguła i powód</Th>
              <Th>Decyzja</Th>
            </tr>
          </thead>
          <tbody>
            {actions.map((action) => (
              <tr key={action.id}>
                <Td className="font-medium">{action.target}</Td>
                <Td>
                  {action.tool}, porty {action.params.ports}
                  <br />
                  <Badge variant="warn">{LEVELS[action.intrusiveness]}</Badge>
                </Td>
                <Td>
                  <span className="font-mono text-xs">{action.rule_name}</span>
                  <br />
                  <span className="text-muted-foreground">{action.reason}</span>
                </Td>
                <Td>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      disabled={!ready || busy}
                      onClick={() => approve.mutate(action.id)}
                    >
                      Zatwierdź
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={!ready || busy}
                      onClick={() => reject.mutate(action.id)}
                    >
                      Odrzuć
                    </Button>
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </CardContent>
    </Card>
  );
}

/** Prośby menedżerów (moduł 21): zatwierdzenie zleca zwykły skan zakresu. */
function ScanRequests({ requests }: { requests: ScanRequest[] }) {
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const decide = useMutation({
    mutationFn: ({ id, approve }: { id: string; approve: boolean }) =>
      api.decideScanRequest(id, approve, reason.trim()),
    onSuccess: () => {
      setReason("");
      void queryClient.invalidateQueries();
    },
  });
  const pending = requests.filter((r) => r.status === "pending");
  if (requests.length === 0) return null;
  return (
    <Card className={pending.length ? "mb-6 border-amber-300" : "mb-6"} data-demo="scan-requests">
      <CardHeader>
        <CardTitle>Prośby o skanowanie ({pending.length} czeka)</CardTitle>
        <CardDescription>
          Menedżer tylko prosi o skan. Zatwierdzenie uruchamia zwykły skan zakresu: planner,
          scope_guard, poziomy i limity działają jak zawsze. Osoba prosząca dostaje powiadomienie
          po skanie.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {pending.length > 0 && (
          <Input
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Komentarz do decyzji (trafia do audytu i do osoby proszącej)"
            aria-label="Komentarz do decyzji"
            className="max-w-xl"
          />
        )}
        <Table>
          <thead>
            <tr>
              <Th>Kiedy</Th>
              <Th>Kto</Th>
              <Th>Zakres</Th>
              <Th>Powód</Th>
              <Th>Stan</Th>
              <Th />
            </tr>
          </thead>
          <tbody>
            {requests.slice(0, 10).map((r) => (
              <tr key={r.id}>
                <Td>{formatDateTime(r.created_at)}</Td>
                <Td>{r.requested_by}</Td>
                <Td>{r.scope_label}</Td>
                <Td>{r.reason || <span className="text-muted-foreground">brak</span>}</Td>
                <Td>
                  <RequestStatus request={r} />
                </Td>
                <Td>
                  {r.status === "pending" && (
                    <span className="flex gap-2">
                      <Button
                        size="sm"
                        disabled={decide.isPending}
                        onClick={() => decide.mutate({ id: r.id, approve: true })}
                      >
                        Zatwierdź i skanuj
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={decide.isPending}
                        onClick={() => decide.mutate({ id: r.id, approve: false })}
                      >
                        Odrzuć
                      </Button>
                    </span>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
        {decide.error && (
          <p role="alert" className="text-sm text-red-700">
            {decide.error.message}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

export function Scans() {
  const queryClient = useQueryClient();
  const runs = useQuery({
    queryKey: ["scans"],
    queryFn: api.scans,
    refetchInterval: 10_000,
  });
  const awaiting = useQuery({
    queryKey: ["scan-actions", "awaiting_approval"],
    queryFn: () => api.scanActions("awaiting_approval"),
    refetchInterval: 10_000,
  });
  const requests = useQuery({
    queryKey: ["scan-requests", "admin"],
    queryFn: () => api.scanRequests(),
    refetchInterval: 10_000,
  });
  const trigger = useMutation({
    mutationFn: () => api.triggerScan(),
    onSuccess: () => {
      window.setTimeout(() => void queryClient.invalidateQueries(), 4000);
    },
  });

  return (
    <>
      <PageHeader
        title="Skany"
        description="Co zostało zeskanowane, która reguła o tym zdecydowała i jaką decyzję podjęła kontrola zakresu. Plan układa deterministyczny silnik reguł (rules/scan_rules.yaml)."
      />
      <ScanRequests requests={requests.data ?? []} />
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <Button disabled={trigger.isPending} onClick={() => trigger.mutate()}>
          Uruchom skan zakresu
        </Button>
        {trigger.data && (
          <p className="text-sm text-muted-foreground" role="status">
            {trigger.data.detail}. Wynik pojawi się poniżej.
          </p>
        )}
        {trigger.error && (
          <p className="text-sm text-red-700" role="alert">
            {trigger.error.message}
          </p>
        )}
      </div>

      {awaiting.data && awaiting.data.length > 0 && <Approvals actions={awaiting.data} />}

      <QueryState
        isPending={runs.isPending}
        error={runs.error}
        empty={runs.data?.length === 0}
        emptyText="Nie było jeszcze żadnego skanu."
      />
      <div className="space-y-6">
        {runs.data?.map((run) => (
          <Card key={run.id}>
            <CardHeader>
              <div className="flex flex-wrap items-center gap-2">
                <CardTitle>Skan z {formatDateTime(run.started_at)}</CardTitle>
                <Badge variant={run.status === "done" ? "ok" : "info"}>
                  {run.status === "done" ? "zakończony" : "w toku"}
                </Badge>
                <Badge variant="neutral">uruchomiony: {TRIGGERS[run.trigger] ?? run.trigger}</Badge>
              </div>
              <CardDescription>
                {typeof run.summary.addresses_done === "number" && (
                  <span>Postęp: {run.summary.addresses_done}/{String(run.summary.total_addresses ?? "?")} adresów; czas: {String(run.summary.duration_seconds ?? "w toku")} s; ETA: {String(run.summary.eta_seconds ?? "?")} s. </span>
                )}
                {typeof run.summary.note === "string" && run.summary.note
                  ? run.summary.note
                  : `Odpowiada hostów: ${String(run.summary.hosts_up ?? 0)}, nowych: ${String(
                      run.summary.hosts_new ?? 0,
                    )}, nie odpowiada: ${String(run.summary.hosts_missing ?? 0)}. Nowe zagrożenia: ${String(
                      run.summary.findings_created ?? 0,
                    )}, powiadomienia: ${String(run.summary.notifications ?? 0)}.`}
              </CardDescription>
            </CardHeader>
            {run.actions.length > 0 && (
              <Table>
                <thead>
                  <tr>
                    <Th>Cel</Th>
                    <Th>Reguła</Th>
                    <Th>Poziom</Th>
                    <Th>Stan</Th>
                    <Th>Zgoda</Th>
                    <Th>Wynik</Th>
                  </tr>
                </thead>
                <tbody>
                  {run.actions.map((action) => (
                    <tr key={action.id}>
                      <Td className="font-medium whitespace-nowrap">{action.target}</Td>
                      <Td>
                        <span className="font-mono text-xs">{action.rule_name}</span>
                        <br />
                        <span className="text-xs text-muted-foreground">{action.reason}</span>
                      </Td>
                      <Td className="whitespace-nowrap">{LEVELS[action.intrusiveness]}</Td>
                      <Td>
                        <StatusBadge status={action.status} />
                      </Td>
                      <Td>
                        {action.approval_source ??
                          (action.intrusiveness >= 2 ? "brak" : "niewymagana")}
                      </Td>
                      <Td className="text-muted-foreground">{action.detail}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
        ))}
      </div>
    </>
  );
}
