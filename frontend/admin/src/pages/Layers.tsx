/** Skanowanie podatności w trzech wyraźnie oddzielonych warstwach (docs/WARSTWY.md).
 *  Każda warstwa ma własny przycisk i własne uprawnienie; żadna nie startuje sama. */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, Brain, Crosshair, Send } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

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
import { Input } from "@shared/components/ui/input";
import { Table, Td, Th } from "@shared/components/ui/table";
import {
  api,
  type LayerAccess,
  type RedteamAnalysis,
  type RedteamGroup,
  type RedteamLayer,
  type RedteamRunDetail,
  type Severity,
} from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";
import { formatDateTime } from "@shared/lib/utils";

import { SEVERITY_LABEL, SEVERITY_VARIANT } from "@/labels";

const STATUS_LABEL = {
  queued: "w kolejce",
  running: "trwa",
  done: "zakończony",
  failed: "błąd",
} as const;

function AccessNote({ access }: { access: LayerAccess }) {
  if (!access.allowed) {
    return (
      <p className="text-sm text-muted-foreground">
        Brak dostępu. Domyślnie tylko administrator; poproś o delegację w IAM.
      </p>
    );
  }
  if (access.via === "rola") {
    return (
      <p className="text-sm text-muted-foreground">
        <Badge variant="info">z roli</Badge> cały zakres skanowania
      </p>
    );
  }
  return (
    <p className="text-sm text-muted-foreground">
      <Badge variant="ok">delegacja</Badge>{" "}
      <span className="font-mono text-xs">{access.scope?.join(", ")}</span>
      {access.until && <> do {formatDateTime(access.until)}</>}
    </p>
  );
}

function Layer1Card({ layer }: { layer: RedteamLayer }) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [targets, setTargets] = useState(layer.access.scope?.join(", ") ?? "");
  const [reason, setReason] = useState("");
  const start = useMutation({
    mutationFn: () =>
      api.startLayer1(
        targets
          .split(/[\s,;]+/)
          .map((t) => t.trim())
          .filter(Boolean),
        reason.trim(),
      ),
    onSuccess: (run) => {
      void queryClient.invalidateQueries({ queryKey: ["redteam"] });
      navigate(`/warstwy/${run.id}`);
    },
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    start.mutate();
  }
  return (
    <Card className="flex flex-col" data-testid="layer-1">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Crosshair className="size-4" /> Warstwa 1: skan deterministyczny
        </CardTitle>
        <CardDescription>{layer.description}</CardDescription>
      </CardHeader>
      <CardContent className="mt-auto space-y-3">
        <AccessNote access={layer.access} />
        {layer.access.allowed && (
          <form onSubmit={submit} className="space-y-2" aria-label="Uruchom warstwę 1">
            <label className="block text-xs font-medium">
              Cele (IP albo CIDR)
              <Input
                className="mt-1 font-mono"
                required
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                placeholder="np. 10.20.0.0/28"
              />
            </label>
            <label className="block text-xs font-medium">
              Powód (do audytu i zgody scope_guard)
              <Input
                className="mt-1"
                required
                minLength={3}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </label>
            <Button type="submit" disabled={start.isPending}>
              Uruchom warstwę 1
            </Button>
            {start.error && (
              <p role="alert" className="text-sm text-red-700">
                {start.error.message}
              </p>
            )}
          </form>
        )}
      </CardContent>
    </Card>
  );
}

function Layer2Card({ layer }: { layer: RedteamLayer }) {
  return (
    <Card className="flex flex-col" data-testid="layer-2">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Brain className="size-4" /> Warstwa 2: analiza LLM
        </CardTitle>
        <CardDescription>{layer.description}</CardDescription>
      </CardHeader>
      <CardContent className="mt-auto space-y-2">
        <AccessNote access={layer.access} />
        <p className="text-sm">
          Uruchamiasz ją przyciskiem „Analizuj (warstwa 2)” w zakończonym przebiegu warstwy 1. Bez
          podłączonego modelu zalecenia pochodzą z szablonu reguł i są tak oznaczone.
        </p>
      </CardContent>
    </Card>
  );
}

function Layer3Card({ layer }: { layer: RedteamLayer }) {
  return (
    <Card className="flex flex-col" data-testid="layer-3">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bot className="size-4" /> Warstwa 3: autonomiczny agent AI
        </CardTitle>
        <CardDescription>{layer.description}</CardDescription>
      </CardHeader>
      <CardContent className="mt-auto space-y-2">
        <AccessNote access={layer.access} />
        <p className="text-sm">
          <Link to="/agent" className="underline">
            Zleć zadanie agentowi
          </Link>{" "}
          (zakładka Agent AI). Zdolności agenta nadaje administrator w IAM, zakładka Non-human.
        </p>
      </CardContent>
    </Card>
  );
}

export function Layers() {
  const layers = useQuery({ queryKey: ["redteam", "layers"], queryFn: api.redteamLayers });
  const runs = useQuery({
    queryKey: ["redteam", "runs"],
    queryFn: api.redteamRuns,
    refetchInterval: (query) =>
      query.state.data?.some((r) => r.status === "queued" || r.status === "running") ? 3000 : false,
  });
  const byLayer = (n: number) => layers.data?.find((l) => l.layer === n);
  return (
    <>
      <PageHeader
        title="Skanowanie podatności: trzy warstwy"
        description="Warstwa 1 skanuje deterministycznie, warstwa 2 analizuje jej logi modelem, warstwa 3 to autonomiczny agent. Każdą uruchamia się osobno i tylko jawnie."
      />
      <QueryState isPending={layers.isPending} error={layers.error} empty={false} emptyText="" />
      {layers.data && (
        <div className="mb-6 grid gap-4 lg:grid-cols-3">
          {byLayer(1) && <Layer1Card layer={byLayer(1)!} />}
          {byLayer(2) && <Layer2Card layer={byLayer(2)!} />}
          {byLayer(3) && <Layer3Card layer={byLayer(3)!} />}
        </div>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Przebiegi warstwy 1</CardTitle>
        </CardHeader>
        <QueryState
          isPending={runs.isPending}
          error={runs.error}
          empty={runs.data?.length === 0}
          emptyText="Warstwa 1 nie była jeszcze uruchamiana."
        />
        {runs.data && runs.data.length > 0 && (
          <Table>
            <thead>
              <tr>
                <Th>Start</Th>
                <Th>Cele</Th>
                <Th>Stan</Th>
                <Th>Hosty</Th>
                <Th>Grupy / podatności</Th>
                <Th>Uruchomił</Th>
              </tr>
            </thead>
            <tbody>
              {runs.data.map((run) => (
                <tr key={run.id}>
                  <Td className="whitespace-nowrap">
                    <Link className="underline" to={`/warstwy/${run.id}`}>
                      {formatDateTime(run.created_at)}
                    </Link>
                  </Td>
                  <Td className="font-mono text-xs">{run.targets.join(", ")}</Td>
                  <Td>
                    <Badge
                      variant={
                        run.status === "done" ? "ok" : run.status === "failed" ? "danger" : "info"
                      }
                    >
                      {STATUS_LABEL[run.status]}
                    </Badge>
                  </Td>
                  <Td>{run.hosts}</Td>
                  <Td>
                    {run.summary.groups ?? 0} / {run.summary.findings ?? 0}
                  </Td>
                  <Td className="text-xs">
                    {run.requested_by}
                    {run.via_delegation && " (delegacja)"}
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

function GroupRow({ group, advice }: { group: RedteamGroup; advice?: RedteamAnalysisAdvice }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr>
        <Td>
          <button
            type="button"
            className="text-left font-medium underline-offset-2 hover:underline"
            aria-expanded={open}
            onClick={() => setOpen(!open)}
          >
            {group.title}
          </button>
          <p className="font-mono text-xs text-muted-foreground">{group.group_key}</p>
        </Td>
        <Td>
          <Badge variant={SEVERITY_VARIANT[group.severity]}>{SEVERITY_LABEL[group.severity]}</Badge>
        </Td>
        <Td>{group.category}</Td>
        <Td>
          {group.unique_hosts} hostów · {group.count} wystąpień
        </Td>
      </tr>
      {open && (
        <tr>
          <Td colSpan={4} className="bg-muted/40">
            <ul className="space-y-1 text-xs">
              {group.hosts.map((h) => (
                <li key={`${h.ip}:${h.port}`}>
                  <span className="font-mono">
                    {h.ip}:{h.port}/{h.protocol}
                  </span>{" "}
                  {h.service} · {h.evidence.join("; ")}
                </li>
              ))}
            </ul>
            {advice && (
              <div className="mt-2 text-sm">
                <p className="font-medium">
                  Zalecenie warstwy 2{" "}
                  <Badge variant={advice.source === "model" ? "info" : "neutral"}>
                    {advice.source === "model" ? "model" : "szablon"}
                  </Badge>
                </p>
                <p>{advice.risk}</p>
                <ul className="list-disc pl-5">
                  {advice.steps.map((s) => (
                    <li key={s}>{s}</li>
                  ))}
                </ul>
              </div>
            )}
          </Td>
        </tr>
      )}
    </>
  );
}

type RedteamAnalysisAdvice = NonNullable<RedteamAnalysis["content"]["groups"]>[number];

function AnalysisCard({ run, allowed }: { run: RedteamRunDetail; allowed: boolean }) {
  const queryClient = useQueryClient();
  const request = useMutation({
    mutationFn: () => api.requestAnalysis(run.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["redteam", "run", run.id] }),
  });
  const analysis = run.analysis;
  const busy = analysis?.status === "queued" || analysis?.status === "running";
  return (
    <Card className="mb-6" data-testid="analysis">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Brain className="size-4" /> Warstwa 2: analiza i zalecenia
        </CardTitle>
        <CardDescription>
          Model czyta zapisane logi i wyniki tego przebiegu (adresy zanonimizowane) i daje kroki
          naprawy. Uruchamia się wyłącznie tym przyciskiem.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {allowed && run.status === "done" && (
          <Button disabled={busy || request.isPending} onClick={() => request.mutate()}>
            Analizuj (warstwa 2)
          </Button>
        )}
        {!allowed && (
          <p className="text-sm text-muted-foreground">
            Brak dostępu do warstwy 2 (administrator albo delegacja w IAM).
          </p>
        )}
        {request.error && (
          <p role="alert" className="text-sm text-red-700">
            {request.error.message}
          </p>
        )}
        {analysis && (
          <div className="space-y-2 text-sm">
            <p>
              <Badge variant={analysis.source === "model" ? "info" : "neutral"}>
                {analysis.status !== "done"
                  ? STATUS_LABEL[analysis.status]
                  : analysis.source === "model"
                    ? `model ${analysis.model ?? ""}`
                    : "szablon reguł (bez modelu)"}
              </Badge>{" "}
              <span className="text-xs text-muted-foreground">
                {analysis.requested_by}, {formatDateTime(analysis.created_at)}
              </span>
            </p>
            {analysis.content.summary && <p>{analysis.content.summary}</p>}
            {analysis.content.strategy && analysis.content.strategy.length > 0 && (
              <div>
                <p className="font-medium">Kolejność działań</p>
                <ul className="list-none">
                  {analysis.content.strategy.map((s) => (
                    <li key={s}>{s}</li>
                  ))}
                </ul>
              </div>
            )}
            {analysis.content.problems?.map((p) => (
              <p key={p} className="text-xs text-muted-foreground">
                {p}
              </p>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function LayerRun() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const run = useQuery({
    queryKey: ["redteam", "run", id],
    queryFn: () => api.redteamRun(id),
    refetchInterval: (query) => {
      const data = query.state.data;
      const busy =
        data &&
        (data.status === "queued" ||
          data.status === "running" ||
          data.analysis?.status === "queued" ||
          data.analysis?.status === "running");
      return busy ? 3000 : false;
    },
  });
  const layers = useQuery({ queryKey: ["redteam", "layers"], queryFn: api.redteamLayers });
  const dojo = useMutation({
    mutationFn: () => api.redteamToDojo(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["redteam", "run", id] }),
  });
  const layer2 = layers.data?.find((l) => l.layer === 2)?.access.allowed ?? false;
  const data = run.data;
  const advice = new Map(
    (data?.analysis?.content.groups ?? []).map((a) => [a.group_key, a] as const),
  );
  return (
    <>
      <PageHeader
        title="Przebieg warstwy 1"
        description="Zgrupowane podatności z deterministycznego skanu, log narzędzi, analiza warstwy 2 i eksport do DefectDojo."
      />
      <p className="mb-3 text-sm">
        <Link to="/warstwy" className="underline">
          ← Wszystkie przebiegi
        </Link>
      </p>
      <QueryState isPending={run.isPending} error={run.error} empty={false} emptyText="" />
      {data && (
        <>
          <Card className="mb-6">
            <CardContent className="flex flex-wrap items-center gap-4 pt-6 text-sm">
              <Badge
                variant={
                  data.status === "done" ? "ok" : data.status === "failed" ? "danger" : "info"
                }
              >
                {STATUS_LABEL[data.status]}
              </Badge>
              <span className="font-mono text-xs">{data.targets.join(", ")}</span>
              <span>{data.hosts} hostów</span>
              {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) =>
                data.summary.by_severity?.[s] ? (
                  <Badge key={s} variant={SEVERITY_VARIANT[s]}>
                    {SEVERITY_LABEL[s]}: {data.summary.by_severity[s]}
                  </Badge>
                ) : null,
              )}
              <span className="text-xs text-muted-foreground">
                {data.requested_by}: {data.reason}
              </span>
              {can("defectdojo:export") && data.status === "done" && (
                <Button
                  size="sm"
                  variant="outline"
                  className="ml-auto"
                  disabled={dojo.isPending || data.groups.length === 0}
                  onClick={() => dojo.mutate()}
                >
                  <Send className="size-3" /> Wyślij grupy do DefectDojo
                </Button>
              )}
            </CardContent>
            {data.error && <p className="px-6 pb-4 text-sm text-red-700">{data.error}</p>}
            {dojo.data && (
              <p role="status" className="px-6 pb-4 text-sm text-muted-foreground">
                {dojo.data.sent > 0
                  ? `Wysłano ${dojo.data.sent} zgrupowanych findingów do DefectDojo.`
                  : (dojo.data.detail ?? "Nic nowego do wysłania")}
              </p>
            )}
            {dojo.error && (
              <p role="alert" className="px-6 pb-4 text-sm text-red-700">
                {dojo.error.message}
              </p>
            )}
          </Card>
          <Card className="mb-6">
            <CardHeader>
              <CardTitle>Podatności zgrupowane po rodzaju problemu</CardTitle>
              <CardDescription>
                Jedna grupa = jeden problem na wszystkich hostach, na których wystąpił. Kliknij
                nazwę, żeby zobaczyć punkty końcowe i dowody.
              </CardDescription>
            </CardHeader>
            {data.groups.length === 0 ? (
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  {data.status === "done" ? "Brak podatności." : "Skan jeszcze trwa…"}
                </p>
              </CardContent>
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Problem</Th>
                    <Th>Ważność</Th>
                    <Th>Kategoria</Th>
                    <Th>Zasięg</Th>
                  </tr>
                </thead>
                <tbody>
                  {data.groups.map((g) => (
                    <GroupRow key={g.group_key} group={g} advice={advice.get(g.group_key)} />
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
          <AnalysisCard run={data} allowed={layer2} />
          <Card>
            <CardHeader>
              <CardTitle>Log narzędzi</CardTitle>
              <CardDescription>
                Polecenia, decyzje scope_guard i surowe wyjście skryptów. To ten log czyta warstwa
                2.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <pre className="max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs">
                {JSON.stringify(data.log, null, 2)}
              </pre>
            </CardContent>
          </Card>
        </>
      )}
    </>
  );
}
