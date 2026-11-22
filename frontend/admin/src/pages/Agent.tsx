import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { PageHeader, QueryState } from "@shared/components/page";
import { Badge } from "@shared/components/ui/badge";
import { Button } from "@shared/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@shared/components/ui/card";
import { Input } from "@shared/components/ui/input";
import { Table, Td, Th } from "@shared/components/ui/table";
import { api, type AgentStatus, type AgentStep, type AgentTask } from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";
import { SignedBy } from "@shared/lib/auth";
import { formatDateTime } from "@shared/lib/utils";

type Variant = "ok" | "warn" | "danger" | "neutral" | "info";

const TASK_STATUS: Record<string, { label: string; variant: Variant }> = {
  planning: { label: "Planowanie", variant: "info" },
  awaiting_approval: { label: "Czeka na zgodę", variant: "warn" },
  approved: { label: "Zatwierdzone", variant: "info" },
  running: { label: "W toku", variant: "info" },
  done: { label: "Zakończone", variant: "ok" },
  failed: { label: "Bez wyniku", variant: "danger" },
  rejected: { label: "Odrzucone", variant: "neutral" },
  killed: { label: "Zatrzymane kill switchem", variant: "danger" },
};

const STEP_STATUS: Record<string, { label: string; variant: Variant }> = {
  planned: { label: "Do decyzji", variant: "warn" },
  blocked: { label: "Zablokowany przez politykę", variant: "danger" },
  approved: { label: "Zatwierdzony", variant: "info" },
  running: { label: "W toku", variant: "info" },
  done: { label: "Wykonany", variant: "ok" },
  failed: { label: "Błąd narzędzia", variant: "danger" },
  skipped: { label: "Pominięty", variant: "neutral" },
};

const LEVELS: Record<number, string> = { 0: "L0", 1: "L1 lekki", 2: "L2 inwazyjny", 3: "L3" };
const SOURCES: Record<string, string> = {
  model: "plan modelu",
  template: "plan z szablonu",
  follow_up: "krok uzupełniający",
};

function StatusBadge({
  status,
  map,
}: {
  status: string;
  map: Record<string, { label: string; variant: Variant }>;
}) {
  const item = map[status] ?? { label: status, variant: "neutral" as const };
  return <Badge variant={item.variant}>{item.label}</Badge>;
}

function refreshSoon(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries();
  window.setTimeout(() => void queryClient.invalidateQueries(), 3000);
  window.setTimeout(() => void queryClient.invalidateQueries(), 8000);
}

/** Stan agenta i kill switch. Wyłączenie działa od razu: MCP odrzuca wywołania, zadania stają. */
function StatusCard({ status }: { status: AgentStatus }) {
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const kill = useMutation({
    mutationFn: () => api.killAgent(reason.trim()),
    onSuccess: () => {
      setReason("");
      refreshSoon(queryClient);
    },
  });
  const capability = status.capability;
  return (
    <Card className={status.killed ? "mb-6 border-red-300" : "mb-6"}>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <CardTitle>Stan agenta</CardTitle>
          {status.killed ? (
            <Badge variant="danger">wyłączony kill switchem</Badge>
          ) : capability ? (
            <Badge variant="ok">aktywny, zdolności v{capability.version}</Badge>
          ) : (
            <Badge variant="warn">bez aktywnych zdolności</Badge>
          )}
          {status.config && (
            <Badge variant={status.config.state === "forced" ? "warn" : "neutral"}>
              {status.config.state === "forced" ? "konfiguracja wymuszona" : "konfiguracja po teście"}
            </Badge>
          )}
        </div>
        <CardDescription>
          {status.killed
            ? `Wyłączył: ${status.killed_by ?? "?"}${
                status.killed_at ? `, ${formatDateTime(status.killed_at)}` : ""
              }. Powód: ${status.killed_reason ?? "brak"}. Ponowne włączenie wymaga nowej wersji zdolności, która przejdzie test agenta.`
            : "Agent proponuje plan, a człowiek go zatwierdza. Każde wywołanie narzędzia przechodzi przez politykę serwera MCP i kontrolę zakresu."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {capability && (
          <dl className="mb-4 grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[auto_1fr]">
            <dt className="text-muted-foreground">Narzędzia</dt>
            <dd className="font-mono text-xs">{capability.tools.join(", ")}</dd>
            <dt className="text-muted-foreground">Cele</dt>
            <dd className="font-mono text-xs">{capability.targets.join(", ")}</dd>
            <dt className="text-muted-foreground">Najwyższy poziom</dt>
            <dd>{LEVELS[capability.max_level]}</dd>
            <dt className="text-muted-foreground">Limity</dt>
            <dd>
              {capability.max_calls_per_task} wywołań na zadanie, {capability.max_calls_per_target}{" "}
              na jeden cel
            </dd>
            {status.config && (
              <>
                <dt className="text-muted-foreground">Model i prompt</dt>
                <dd className="font-mono text-xs">
                  {status.config.model || "bez modelu (plan z szablonu)"}, {status.config.prompt_version}
                </dd>
              </>
            )}
          </dl>
        )}
        {status.pending.length > 0 && (
          <p className="mb-4 text-sm text-amber-800">
            Nowa konfiguracja czeka na test agenta ({status.pending.length}). Do czasu zaliczenia
            obowiązuje poprzednia. Szczegóły: <Link className="underline" to="/agent/test">Test agenta</Link>.
          </p>
        )}
        {status.killed && <KillEffects status={status} />}
        {!status.killed && (
          <div className="flex flex-wrap items-end gap-3 border-t pt-4">
            <label className="min-w-64 flex-1 text-xs font-medium">
              Powód wyłączenia (wymagany)
              <Input
                className="mt-1"
                maxLength={2000}
                placeholder="np. podejrzane zachowanie agenta"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </label>
            <Button
              variant="destructive"
              disabled={reason.trim().length < 3 || kill.isPending}
              onClick={() => kill.mutate()}
            >
              Kill switch: wyłącz agenta
            </Button>
            <p className="w-full text-xs text-muted-foreground">
              Kill switch od razu blokuje każde wywołanie, przerywa trwające skany, wyłącza konto
              agenta w Keycloak i odwołuje jego tokeny w OpenBao.{" "}
              <strong className="text-foreground">Luka: {status.certificate_gap}</strong>
            </p>
          </div>
        )}
        {kill.error && (
          <p className="mt-2 text-sm text-red-700" role="alert">
            {kill.error.message}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

const EFFECT_LABELS: Record<string, string> = {
  keycloak: "Keycloak: konto agenta",
  openbao: "OpenBao: tokeny serwera MCP",
};

function KillEffects({ status }: { status: AgentStatus }) {
  return (
    <div className="mb-2 rounded-md border border-red-200 bg-red-50 p-3 text-sm">
      <p className="mb-2 font-medium">Skutki kill switcha</p>
      <ul className="space-y-1">
        <li>
          <Badge variant="ok">od razu</Badge> Flaga w bazie: serwer MCP, walidator i wykonawca
          odrzucają każde wywołanie.
        </li>
        {status.effects.length === 0 && (
          <li className="text-muted-foreground">Keycloak i OpenBao: trwa…</li>
        )}
        {status.effects.map((effect) => (
          <li key={effect.name}>
            <Badge variant={effect.ok ? "ok" : "danger"}>{effect.ok ? "wykonano" : "błąd"}</Badge>{" "}
            {EFFECT_LABELS[effect.name] ?? effect.name}: {effect.detail}
          </li>
        ))}
        <li>
          {status.scanner_stopped_at ? (
            <>
              <Badge variant="ok">potwierdzono</Badge> mcp-scanner przerwał trwające wywołania (
              {status.scanner_stopped ?? 0}), {formatDateTime(status.scanner_stopped_at)}.
            </>
          ) : (
            <>
              <Badge variant="warn">czekam</Badge> mcp-scanner jeszcze nie potwierdził zatrzymania
              (sprawdza co sekundę).
            </>
          )}
        </li>
      </ul>
      <p className="mt-2 font-medium text-red-800">Luka: {status.certificate_gap}</p>
    </div>
  );
}

function NewTask({ disabled }: { disabled: boolean }) {
  const queryClient = useQueryClient();
  const layer3 = useAuth().can("redteam:layer3");
  const [command, setCommand] = useState("");
  const create = useMutation({
    mutationFn: () => api.createAgentTask(command.trim()),
    onSuccess: () => {
      setCommand("");
      refreshSoon(queryClient);
    },
  });
  return (
    <Card className="mb-6">
      <CardHeader>
        <CardTitle>Nowe zadanie</CardTitle>
        <CardDescription>
          Polecenie w zwykłym języku, np. „Zrób assessment hosta 172.30.99.16 i zbierz pakiety
          przez SSH”. Agent ułoży plan, walidator sprawdzi go z polityką i zakresem, a Ty
          zdecydujesz o każdym kroku.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap items-end gap-3">
          <Input
            className="min-w-64 flex-1"
            maxLength={4000}
            placeholder="Polecenie dla agenta"
            value={command}
            onChange={(e) => setCommand(e.target.value)}
          />
          <Button
            disabled={disabled || !layer3 || command.trim().length < 3 || create.isPending}
            onClick={() => create.mutate()}
          >
            Zleć zadanie
          </Button>
        </div>
        {disabled && (
          <p className="mt-2 text-sm text-muted-foreground">
            Agent nie przyjmuje zadań: brak aktywnych zdolności albo włączony kill switch.
          </p>
        )}
        {!layer3 && (
          <p className="mt-2 text-sm text-muted-foreground">
            Agent to warstwa 3: zadanie zleca administrator albo osoba z delegacją warstwy 3 w IAM.
          </p>
        )}
        {create.error && (
          <p className="mt-2 text-sm text-red-700" role="alert">
            {create.error.message}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function resultText(step: AgentStep): string {
  const result = step.result ?? {};
  if (typeof result.error === "string") return result.error;
  if (typeof result.reason === "string" && step.status !== "done") return result.reason;
  const parts: string[] = [];
  if (Array.isArray(result.hosts_up)) parts.push(`odpowiada hostów: ${result.hosts_up.length}`);
  if (Array.isArray(result.new_hosts) && result.new_hosts.length > 0)
    parts.push(`nowe: ${result.new_hosts.length}`);
  if (Array.isArray(result.open_ports)) parts.push(`otwarte porty: ${result.open_ports.join(", ")}`);
  if (typeof result.packages === "number") parts.push(`pakiety: ${result.packages}`);
  if (typeof result.new_packages === "number" && result.new_packages > 0)
    parts.push(`nowe pakiety: ${result.new_packages}`);
  if (typeof result.confirmed === "boolean")
    parts.push(result.confirmed ? "podatność potwierdzona wersją" : "niepotwierdzona");
  if (typeof result.status === "number") parts.push(`HTTP ${result.status}`);
  if (result.untrusted && typeof result.untrusted === "object") parts.push("treść z hosta: niezaufana");
  return parts.join(", ");
}

function TaskCard({ task }: { task: AgentTask }) {
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const [chosen, setChosen] = useState<Set<string> | null>(null);
  const pending = task.steps.filter((s) => s.status === "planned");
  const selected = chosen ?? new Set(pending.map((s) => s.id));
  const onDone = () => {
    setReason("");
    setChosen(null);
    refreshSoon(queryClient);
  };
  const approve = useMutation({
    mutationFn: () => api.approveAgentTask(task.id, reason.trim(), [...selected]),
    onSuccess: onDone,
  });
  const reject = useMutation({
    mutationFn: () => api.rejectAgentTask(task.id, reason.trim()),
    onSuccess: onDone,
  });
  const awaiting = task.status === "awaiting_approval";
  const busy = approve.isPending || reject.isPending;
  const failure = approve.error ?? reject.error;
  const toggle = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setChosen(next);
  };

  return (
    <Card className={awaiting ? "border-amber-300" : undefined} data-demo="agent-task">
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <CardTitle className="text-base tracking-normal text-foreground normal-case">„{task.command}”</CardTitle>
          <StatusBadge status={task.status} map={TASK_STATUS} />
          {task.plan_source && (
            <Badge variant="neutral">{SOURCES[task.plan_source] ?? task.plan_source}</Badge>
          )}
        </div>
        <CardDescription>
          Zlecił {task.created_by}, {formatDateTime(task.created_at)}
          {task.approved_by && `. Zatwierdził ${task.approved_by}: ${task.approval_reason ?? ""}`}
          {task.plan_problems.length > 0 && `. Walidator: ${task.plan_problems.join("; ")}`}
        </CardDescription>
      </CardHeader>
      {task.steps.length > 0 && (
        <Table>
          <thead>
            <tr>
              {awaiting && <Th>Zgoda</Th>}
              <Th>Krok</Th>
              <Th>Cel</Th>
              <Th>Poziom</Th>
              <Th>Uzasadnienie</Th>
              <Th>Stan</Th>
              <Th>Wynik</Th>
            </tr>
          </thead>
          <tbody>
            {task.steps.map((step) => (
              <tr key={step.id}>
                {awaiting && (
                  <Td>
                    {step.status === "planned" && (
                      <input
                        type="checkbox"
                        aria-label={`Zatwierdź krok ${step.position}`}
                        checked={selected.has(step.id)}
                        onChange={() => toggle(step.id)}
                      />
                    )}
                  </Td>
                )}
                <Td>
                  <span className="font-mono text-xs">{step.tool}</span>
                  {step.source === "follow_up" && (
                    <>
                      <br />
                      <span className="text-xs text-muted-foreground">uzupełniający</span>
                    </>
                  )}
                </Td>
                <Td className="font-medium whitespace-nowrap">{step.target}</Td>
                <Td className="whitespace-nowrap">
                  <Badge variant={step.level >= 2 ? "warn" : "neutral"}>{LEVELS[step.level]}</Badge>
                </Td>
                <Td className="text-muted-foreground">{step.reason}</Td>
                <Td>
                  <StatusBadge status={step.status} map={STEP_STATUS} />
                  {step.decision_reason && step.status === "blocked" && (
                    <p className="mt-1 text-xs text-muted-foreground">{step.decision_reason}</p>
                  )}
                </Td>
                <Td className="text-xs text-muted-foreground">{resultText(step)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {awaiting && (
        <CardContent className="pt-4">
          <div className="flex flex-wrap items-end gap-3">
            <SignedBy />
            <label className="min-w-64 flex-1 text-xs font-medium">
              Uzasadnienie decyzji (wymagane)
              <Input
                className="mt-1"
                maxLength={2000}
                placeholder="np. assessment uzgodniony z właścicielem hosta"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </label>
            <Button
              disabled={reason.trim().length < 3 || selected.size === 0 || busy}
              onClick={() => approve.mutate()}
            >
              Zatwierdź wybrane ({selected.size})
            </Button>
            <Button
              variant="outline"
              disabled={reason.trim().length < 3 || busy}
              onClick={() => reject.mutate()}
            >
              Odrzuć zadanie
            </Button>
          </div>
          <p className="mt-2 text-xs text-muted-foreground">
            Kroki L2 wymagają uprawnienia do zgody na ten poziom. Po zatwierdzeniu każde wywołanie
            i tak przechodzi przez politykę MCP i kontrolę zakresu.
          </p>
          {failure && (
            <p className="mt-2 text-sm text-red-700" role="alert">
              {failure.message}
            </p>
          )}
        </CardContent>
      )}
    </Card>
  );
}

function Leases() {
  const leases = useQuery({ queryKey: ["agent-leases"], queryFn: api.agentLeases });
  return (
    <Card className="mt-6" data-demo="agent-leases">
      <CardHeader>
        <CardTitle>Poświadczenia just-in-time</CardTitle>
        <CardDescription>
          Certyfikaty SSH z OpenBao: jeden na krok, ważne 15 minut, unieważniane po kroku. Klucz
          prywatny nie opuszcza serwera MCP i nie trafia do modelu, logów ani API.
        </CardDescription>
      </CardHeader>
      <QueryState
        isPending={leases.isPending}
        error={leases.error}
        empty={leases.data?.length === 0}
        emptyText="Agent nie dostał jeszcze żadnego poświadczenia."
      />
      {leases.data && leases.data.length > 0 && (
        <Table>
          <thead>
            <tr>
              <Th>Cel</Th>
              <Th>Użytkownik</Th>
              <Th>Wydany</Th>
              <Th>Ważny do</Th>
              <Th>Unieważniony</Th>
            </tr>
          </thead>
          <tbody>
            {leases.data.map((lease) => (
              <tr key={lease.id}>
                <Td className="font-medium">{lease.target}</Td>
                <Td className="font-mono text-xs">{lease.principal}</Td>
                <Td>{formatDateTime(lease.issued_at)}</Td>
                <Td>{formatDateTime(lease.expires_at)}</Td>
                <Td>
                  {lease.revoked_at ? (
                    <Badge variant="ok">{formatDateTime(lease.revoked_at)}</Badge>
                  ) : (
                    <Badge variant="warn">nie (wygaśnie sam)</Badge>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

export function Agent() {
  const status = useQuery({
    queryKey: ["agent-status"],
    queryFn: api.agentStatus,
    refetchInterval: 10_000,
  });
  const tasks = useQuery({
    queryKey: ["agent-tasks"],
    queryFn: api.agentTasks,
    refetchInterval: 5_000,
  });
  const ready = Boolean(status.data && !status.data.killed && status.data.capability);

  return (
    <>
      <PageHeader
        title="Agent AI"
        description="Agent układa plan z polecenia, a decyzję o każdym kroku L2 podejmuje człowiek. Narzędzia działają wyłącznie przez serwer MCP, który sprawdza politykę i zakres przy każdym wywołaniu."
      />
      <QueryState
        isPending={status.isPending}
        error={status.error}
        empty={false}
        emptyText=""
      />
      {status.data && <StatusCard status={status.data} />}
      <NewTask disabled={!ready} />
      <h2 className="mb-3 text-base font-semibold">Zadania</h2>
      <QueryState
        isPending={tasks.isPending}
        error={tasks.error}
        empty={tasks.data?.length === 0}
        emptyText="Agent nie dostał jeszcze żadnego zadania."
      />
      <div className="space-y-6">
        {tasks.data?.map((task) => <TaskCard key={task.id} task={task} />)}
      </div>
      <Leases />
    </>
  );
}
