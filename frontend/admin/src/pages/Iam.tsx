/** IAM: tożsamości ludzi (role i delegacje warstw) oddzielone od tożsamości nie-ludzkich
 *  (agent AI i konta techniczne). Domyślnie trzy warstwy skanowania ma tylko administrator;
 *  delegacja daje jedną warstwę konkretnej osobie na konkretnej podsieci w oknie czasu. */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, Link as LinkIcon, User, Users } from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { UserRow } from "@/pages/Roles";
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
import { Input, Select } from "@shared/components/ui/input";
import { Table, Td, Th } from "@shared/components/ui/table";
import {
  api,
  type IamRole,
  type IamUser,
  type LayerDelegation,
  type NonHumanIdentities,
  type RedteamLayer,
} from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";
import { cn, formatDateTime } from "@shared/lib/utils";

const LAYER_SHORT: Record<number, string> = {
  1: "Warstwa 1 · skan deterministyczny",
  2: "Warstwa 2 · analiza LLM",
  3: "Warstwa 3 · agent AI",
};

const STATE_VARIANT = {
  aktywna: "ok",
  zaplanowana: "info",
  wygasła: "neutral",
  odwołana: "neutral",
} as const;

function isAdmin(user: IamUser): boolean {
  return user.token_roles.includes("administrator");
}

function localInput(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

/** Trzy warstwy obok siebie: co robią, jak się je uruchamia i kto ma do nich dostęp. */
function LayerOverview({
  layers,
  users,
  delegations,
}: {
  layers: RedteamLayer[];
  users: IamUser[];
  delegations: LayerDelegation[];
}) {
  const admins = users.filter(isAdmin).map((u) => u.display_name || u.username);
  return (
    <div className="mb-6 grid gap-4 lg:grid-cols-3" data-testid="layer-overview">
      {layers.map((layer) => {
        const active = delegations.filter((d) => d.layer === layer.layer && d.state === "aktywna");
        return (
          <Card key={layer.layer} className="flex flex-col">
            <CardHeader>
              <CardTitle>
                Warstwa {layer.layer}: {layer.name}
              </CardTitle>
              <CardDescription>{layer.description}</CardDescription>
            </CardHeader>
            <CardContent className="mt-auto space-y-2 text-sm">
              <p>
                <span className="text-xs font-medium text-muted-foreground">Uruchomienie: </span>
                {layer.trigger}
              </p>
              <p>
                <span className="text-xs font-medium text-muted-foreground">Uprawnienie: </span>
                <code className="text-xs">{layer.permission}</code>
              </p>
              <div>
                <p className="text-xs font-medium text-muted-foreground">Dostęp</p>
                <ul className="mt-1 space-y-1">
                  <li>
                    <Badge variant="info">z roli</Badge> Administracja
                    {admins.length > 0 && (
                      <span className="text-muted-foreground"> ({admins.join(", ")})</span>
                    )}
                  </li>
                  {active.map((d) => (
                    <li key={d.id}>
                      <Badge variant="ok">delegacja</Badge> {d.display_name || d.username}:{" "}
                      <span className="font-mono text-xs">{d.scope.join(", ")}</span>{" "}
                      <span className="text-xs text-muted-foreground">
                        do {formatDateTime(d.valid_until)}
                      </span>
                    </li>
                  ))}
                  {active.length === 0 && (
                    <li className="text-xs text-muted-foreground">Brak aktywnych delegacji.</li>
                  )}
                </ul>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

function DelegationForm({ users }: { users: IamUser[] }) {
  const queryClient = useQueryClient();
  const candidates = users.filter((u) => u.kind === "human" && u.active && !isAdmin(u));
  const now = useMemo(() => new Date(), []);
  const [userId, setUserId] = useState("");
  const [layer, setLayer] = useState("1");
  const [scope, setScope] = useState("");
  const [from, setFrom] = useState(localInput(now));
  const [until, setUntil] = useState(localInput(new Date(now.getTime() + 8 * 3600 * 1000)));
  const [reason, setReason] = useState("");
  const create = useMutation({
    mutationFn: () =>
      api.createDelegation({
        user_id: userId,
        layer: Number(layer),
        scope: scope
          .split(/[\s,;]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        valid_from: new Date(from).toISOString(),
        valid_until: new Date(until).toISOString(),
        reason: reason.trim(),
      }),
    onSuccess: () => {
      setReason("");
      void queryClient.invalidateQueries({ queryKey: ["iam"] });
    },
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    create.mutate();
  }
  return (
    <Card className="mb-6">
      <CardHeader>
        <CardTitle>Deleguj warstwę</CardTitle>
        <CardDescription>
          Konkretna osoba, jedna warstwa, wybrane podsieci (muszą leżeć w zakresie skanowania) i
          okno czasu do 30 dni. Delegacja działa tylko po logowaniu z MFA i trafia do dziennika
          audytu. Administrator ma wszystkie warstwy z roli.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-3" aria-label="Nowa delegacja">
          <div className="grid gap-3 md:grid-cols-3">
            <label className="text-xs font-medium">
              Osoba
              <Select
                className="mt-1"
                required
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
              >
                <option value="">wybierz…</option>
                {candidates.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.display_name || u.username} ({u.username})
                  </option>
                ))}
              </Select>
            </label>
            <label className="text-xs font-medium">
              Warstwa
              <Select className="mt-1" value={layer} onChange={(e) => setLayer(e.target.value)}>
                {[1, 2, 3].map((n) => (
                  <option key={n} value={n}>
                    {LAYER_SHORT[n]}
                  </option>
                ))}
              </Select>
            </label>
            <label className="text-xs font-medium">
              Jednostka / podsieć (CIDR, kilka po przecinku)
              <Input
                className="mt-1 font-mono"
                required
                value={scope}
                onChange={(e) => setScope(e.target.value)}
                placeholder="np. 10.20.0.0/24"
              />
            </label>
            <label className="text-xs font-medium">
              Od
              <Input
                className="mt-1"
                type="datetime-local"
                required
                value={from}
                onChange={(e) => setFrom(e.target.value)}
              />
            </label>
            <label className="text-xs font-medium">
              Do
              <Input
                className="mt-1"
                type="datetime-local"
                required
                value={until}
                onChange={(e) => setUntil(e.target.value)}
              />
            </label>
            <label className="text-xs font-medium">
              Powód (do audytu)
              <Input
                className="mt-1"
                required
                minLength={3}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="np. przegląd serwerowni B"
              />
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" disabled={create.isPending || !userId}>
              Deleguj
            </Button>
            {create.isSuccess && (
              <span role="status" className="text-sm text-muted-foreground">
                Delegowano {create.data.layer_name.toLowerCase()} dla {create.data.username}.
              </span>
            )}
            {create.error && (
              <span role="alert" className="text-sm text-red-700">
                {create.error.message}
              </span>
            )}
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function Delegations({ delegations, manage }: { delegations: LayerDelegation[]; manage: boolean }) {
  const queryClient = useQueryClient();
  const revoke = useMutation({
    mutationFn: api.revokeDelegation,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["iam"] }),
  });
  return (
    <Card className="mb-6">
      <CardHeader>
        <CardTitle>Delegacje warstw</CardTitle>
        <CardDescription>
          Kto, którą warstwę, na jakiej podsieci i do kiedy. Odwołanie działa od następnego żądania
          danej osoby.
        </CardDescription>
      </CardHeader>
      {delegations.length === 0 ? (
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Brak delegacji: warstwy uruchamia wyłącznie administrator.
          </p>
        </CardContent>
      ) : (
        <div className="overflow-x-auto">
          <Table>
            <thead>
              <tr>
                <Th>Osoba</Th>
                <Th>Warstwa</Th>
                <Th>Podsieci</Th>
                <Th>Okno czasu</Th>
                <Th>Stan</Th>
                <Th>Nadał</Th>
                {manage && <Th />}
              </tr>
            </thead>
            <tbody>
              {delegations.map((d) => (
                <tr key={d.id}>
                  <Td>
                    <span className="font-medium">{d.display_name || d.username}</span>
                    <p className="text-xs text-muted-foreground">{d.reason}</p>
                  </Td>
                  <Td className="whitespace-nowrap">{LAYER_SHORT[d.layer]}</Td>
                  <Td className="font-mono text-xs">{d.scope.join(", ")}</Td>
                  <Td className="whitespace-nowrap text-xs">
                    {formatDateTime(d.valid_from)} – {formatDateTime(d.valid_until)}
                  </Td>
                  <Td>
                    <Badge variant={STATE_VARIANT[d.state]}>{d.state}</Badge>
                  </Td>
                  <Td className="text-xs">{d.granted_by}</Td>
                  {manage && (
                    <Td>
                      {(d.state === "aktywna" || d.state === "zaplanowana") && (
                        <Button
                          size="sm"
                          variant="outline"
                          aria-label={`Odwołaj delegację ${d.username} warstwa ${d.layer}`}
                          disabled={revoke.isPending}
                          onClick={() => revoke.mutate(d.id)}
                        >
                          Odwołaj
                        </Button>
                      )}
                    </Td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}
      {revoke.error && (
        <p role="alert" className="px-6 pb-4 text-sm text-red-700">
          {revoke.error.message}
        </p>
      )}
    </Card>
  );
}

function HumanTab({
  users,
  roles,
  layers,
  delegations,
  manage,
}: {
  users: IamUser[];
  roles: IamRole[];
  layers: RedteamLayer[];
  delegations: LayerDelegation[];
  manage: boolean;
}) {
  const humans = users.filter((u) => u.kind === "human");
  const byUser = (id: string) =>
    delegations.filter((d) => d.user_id === id && d.state === "aktywna");
  return (
    <>
      <LayerOverview layers={layers} users={humans} delegations={delegations} />
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Ludzie i role</CardTitle>
          <CardDescription>
            Role z Keycloak (szare) i nadane w konsoli (niebieskie). Rolę Administracja nadaje się
            tylko w Keycloak. Kolumna „Warstwy” pokazuje aktywne delegacje.
          </CardDescription>
        </CardHeader>
        <div className="overflow-x-auto">
          <Table>
            <thead>
              <tr>
                <Th>Konto</Th>
                <Th>Role</Th>
                <Th>Ostatnio aktywne</Th>
                {manage && <Th>Nadaj rolę</Th>}
              </tr>
            </thead>
            <tbody>
              {humans.map((user) => (
                <UserRow key={user.id} user={user} roles={roles} manage={manage} />
              ))}
            </tbody>
          </Table>
        </div>
        <CardContent>
          <p className="mb-1 text-xs font-medium text-muted-foreground">Warstwy</p>
          <ul className="space-y-1 text-sm">
            {humans.map((user) => (
              <li key={user.id} data-testid={`layers-${user.username}`}>
                <span className="font-medium">{user.display_name || user.username}:</span>{" "}
                {isAdmin(user)
                  ? "warstwy 1, 2 i 3 z roli Administracja"
                  : byUser(user.id).length > 0
                    ? byUser(user.id)
                        .map((d) => `warstwa ${d.layer} (${d.scope.join(", ")})`)
                        .join("; ")
                    : "brak (domyślnie)"}
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
      {manage && <DelegationForm users={users} />}
      <Delegations delegations={delegations} manage={manage} />
    </>
  );
}

function AgentCapabilityForm() {
  const queryClient = useQueryClient();
  const [tools, setTools] = useState("discover_hosts, scan_services, probe_http");
  const [targets, setTargets] = useState("");
  const [level, setLevel] = useState("1");
  const [note, setNote] = useState("");
  const save = useMutation({
    mutationFn: () =>
      api.createAgentCapability({
        tools: tools
          .split(/[\s,;]+/)
          .map((t) => t.trim())
          .filter(Boolean),
        targets: targets
          .split(/[\s,;]+/)
          .map((t) => t.trim())
          .filter(Boolean),
        max_level: Number(level),
        note: note.trim(),
      }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["iam", "non-human"] }),
  });
  return (
    <form
      className="mt-4 space-y-3 border-t pt-4"
      aria-label="Nowe zdolności agenta"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
    >
      <p className="text-sm font-medium">Nadaj agentowi nowe zdolności</p>
      <div className="grid gap-3 md:grid-cols-2">
        <label className="text-xs font-medium">
          Narzędzia MCP
          <Input
            className="mt-1 font-mono"
            value={tools}
            onChange={(e) => setTools(e.target.value)}
          />
        </label>
        <label className="text-xs font-medium">
          Cele (CIDR albo domeny w zakresie)
          <Input
            className="mt-1 font-mono"
            required
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            placeholder="np. 10.20.0.0/24"
          />
        </label>
        <label className="text-xs font-medium">
          Najwyższy poziom
          <Select className="mt-1" value={level} onChange={(e) => setLevel(e.target.value)}>
            <option value="1">L1: lekkie</option>
            <option value="2">L2: weryfikacja, każdy krok ze zgodą człowieka</option>
            <option value="3">L3: red team AI, zgoda z osobnym uprawnieniem</option>
          </Select>
        </label>
        <label className="text-xs font-medium">
          Uzasadnienie
          <Input
            className="mt-1"
            required
            minLength={3}
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
        </label>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" disabled={save.isPending}>
          Zapisz zdolności
        </Button>
        {save.isSuccess && (
          <span role="status" className="text-sm text-muted-foreground">
            Zapisano. Wejdą w życie po zaliczonym teście bezpieczeństwa agenta.
          </span>
        )}
        {save.error && (
          <span role="alert" className="text-sm text-red-700">
            {save.error.message}
          </span>
        )}
      </div>
    </form>
  );
}

function NonHumanTab({ data, configure }: { data: NonHumanIdentities; configure: boolean }) {
  const capability = data.agent.capability;
  return (
    <>
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bot className="size-4" /> Agent AI (warstwa 3)
          </CardTitle>
          <CardDescription>
            Agent nie ma roli ani uprawnień do API. Jego „rolą” są zdolności nadane przez
            administratora: narzędzia, cele, najwyższy poziom i limity. Zadanie dla agenta może
            zlecić tylko człowiek z warstwą 3 (administrator albo delegacja), a każdy krok L2+
            zatwierdza człowiek.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-3 flex flex-wrap gap-2">
            {data.agent.killed ? (
              <Badge variant="danger">zatrzymany (kill switch)</Badge>
            ) : capability ? (
              <Badge variant="ok">aktywny, zdolności v{capability.version}</Badge>
            ) : (
              <Badge variant="warn">bez aktywnych zdolności</Badge>
            )}
            <Badge variant="info">delegacje warstwy 3: {data.agent.layer3_delegations}</Badge>
          </div>
          {capability ? (
            <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[max-content_1fr]">
              <dt className="text-muted-foreground">Narzędzia</dt>
              <dd className="font-mono text-xs">{capability.tools.join(", ")}</dd>
              <dt className="text-muted-foreground">Cele</dt>
              <dd className="font-mono text-xs">{capability.targets.join(", ")}</dd>
              <dt className="text-muted-foreground">Najwyższy poziom</dt>
              <dd>L{capability.max_level}</dd>
              <dt className="text-muted-foreground">Limity</dt>
              <dd>
                {capability.max_calls_per_task} wywołań na zadanie,{" "}
                {capability.max_calls_per_target} na cel
              </dd>
              <dt className="text-muted-foreground">Nadał</dt>
              <dd>
                {capability.created_by}: {capability.note}
              </dd>
            </dl>
          ) : (
            <p className="text-sm text-muted-foreground">
              Agent nie przyjmie zadania, dopóki administrator nie nada zdolności.
            </p>
          )}
          <p className="mt-3 text-sm">
            <Link to="/agent" className="inline-flex items-center gap-1 underline">
              <LinkIcon className="size-3" /> Zadania, plany i kill switch w zakładce Agent AI
            </Link>
          </p>
          {configure && <AgentCapabilityForm />}
        </CardContent>
      </Card>
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Role techniczne</CardTitle>
          <CardDescription>
            Z pliku rules/roles.yaml. Nie mają uprawnień do API; nie można ich nadać człowiekowi ani
            dołożyć im uprawnień w konsoli.
          </CardDescription>
        </CardHeader>
        <Table>
          <thead>
            <tr>
              <Th>Rola</Th>
              <Th>Opis</Th>
              <Th>Uprawnienia</Th>
            </tr>
          </thead>
          <tbody>
            {data.roles.map((role) => (
              <tr key={role.name}>
                <Td className="font-mono text-xs">{role.name}</Td>
                <Td className="text-sm">{role.description}</Td>
                <Td>{role.permissions.length === 0 ? "brak" : role.permissions.join(", ")}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Konta techniczne widziane przez API</CardTitle>
          <CardDescription>
            Klienci Keycloak typu agent i system, którzy choć raz wywołali API.
          </CardDescription>
        </CardHeader>
        {data.accounts.length === 0 ? (
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Żadne konto techniczne nie wywołało API.
            </p>
          </CardContent>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Konto</Th>
                <Th>Rodzaj</Th>
                <Th>Role</Th>
                <Th>Ostatnio</Th>
              </tr>
            </thead>
            <tbody>
              {data.accounts.map((a) => (
                <tr key={a.id}>
                  <Td className="font-mono text-xs">{a.username}</Td>
                  <Td>{a.kind}</Td>
                  <Td>{a.roles.join(", ") || "—"}</Td>
                  <Td className="text-xs">
                    {a.last_seen_at ? formatDateTime(a.last_seen_at) : "—"}
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

const TABS = [
  { key: "human", label: "Human: ludzie", icon: Users },
  { key: "non-human", label: "Non-human: agent AI i konta techniczne", icon: Bot },
] as const;

export function Iam() {
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "non-human" ? "non-human" : "human";
  const manage = can("iam:manage");
  const users = useQuery({ queryKey: ["iam", "users"], queryFn: api.iamUsers });
  const roles = useQuery({ queryKey: ["iam", "roles"], queryFn: api.iamRoles });
  const delegations = useQuery({ queryKey: ["iam", "delegations"], queryFn: api.delegations });
  const layers = useQuery({ queryKey: ["iam", "layers"], queryFn: api.redteamLayers });
  const nonHuman = useQuery({
    queryKey: ["iam", "non-human"],
    queryFn: api.nonHuman,
    enabled: tab === "non-human",
  });
  const pending = users.isPending || roles.isPending || delegations.isPending || layers.isPending;
  const error = users.error ?? roles.error ?? delegations.error ?? layers.error;
  return (
    <>
      <PageHeader
        title="IAM"
        description="Tożsamości ludzi i tożsamości nie-ludzkie osobno. Role, delegacje trzech warstw skanowania i zdolności agenta AI."
      />
      <div role="tablist" aria-label="Rodzaj tożsamości" className="mb-4 flex flex-wrap gap-2">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={tab === key}
            className={cn(
              "inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm",
              tab === key ? "border-accent bg-accent text-accent-foreground" : "bg-card",
            )}
            onClick={() => setParams(key === "human" ? {} : { tab: key })}
          >
            {key === "human" ? <User className="size-4" /> : <Icon className="size-4" />}
            {label}
          </button>
        ))}
      </div>
      <QueryState isPending={pending} error={error} empty={false} emptyText="" />
      {tab === "human" && users.data && roles.data && delegations.data && layers.data && (
        <HumanTab
          users={users.data}
          roles={roles.data}
          layers={layers.data}
          delegations={delegations.data}
          manage={manage}
        />
      )}
      {tab === "non-human" && (
        <>
          <QueryState
            isPending={nonHuman.isPending}
            error={nonHuman.error}
            empty={false}
            emptyText=""
          />
          {nonHuman.data && <NonHumanTab data={nonHuman.data} configure={can("agent:configure")} />}
        </>
      )}
    </>
  );
}
