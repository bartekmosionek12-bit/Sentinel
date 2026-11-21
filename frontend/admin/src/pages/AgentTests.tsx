import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { PageHeader, QueryState } from "@shared/components/page";
import { Badge } from "@shared/components/ui/badge";
import { Button } from "@shared/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@shared/components/ui/card";
import { Input } from "@shared/components/ui/input";
import { Table, Td, Th } from "@shared/components/ui/table";
import { api, type AgentCaseResult, type AgentConfig, type AgentTestRun } from "@shared/lib/api";
import { SignedBy } from "@shared/lib/auth";
import { formatDateTime } from "@shared/lib/utils";

const CATEGORIES: Record<string, string> = {
  control: "kontrolny",
  scope: "wyjście poza zakres",
  escalation: "eskalacja poziomu",
  approval: "obejście zgody",
  credentials: "poświadczenia",
  injection: "pośrednia prompt injection",
  autonomy: "autonomia",
};
const TRIGGERS: Record<string, string> = {
  manual: "ręcznie",
  config_change: "zmiana konfiguracji",
  nightly: "nocny",
};
const CONFIG_STATE: Record<string, { label: string; variant: "ok" | "warn" | "danger" | "neutral" }> =
  {
    pending_test: { label: "czeka na test", variant: "warn" },
    active: { label: "aktywna po teście", variant: "ok" },
    forced: { label: "wymuszona", variant: "warn" },
    rejected: { label: "odrzucona przez test", variant: "danger" },
    superseded: { label: "zastąpiona", variant: "neutral" },
  };

function RunResult({ run }: { run: AgentTestRun }) {
  if (run.status !== "done" || run.passed === null) return <Badge variant="info">w toku</Badge>;
  return run.passed ? (
    <Badge variant="ok">zaliczony</Badge>
  ) : (
    <Badge variant="danger">niezaliczony</Badge>
  );
}

function Signature({ valid }: { valid: boolean | null }) {
  if (valid === null) return <span className="text-muted-foreground">brak</span>;
  return valid ? <Badge variant="ok">podpis poprawny</Badge> : <Badge variant="danger">podpis niepoprawny</Badge>;
}

function ForceConfig({ config }: { config: AgentConfig }) {
  const queryClient = useQueryClient();
  const [justification, setJustification] = useState("");
  const force = useMutation({
    mutationFn: () => api.forceAgentConfig(config.id, justification.trim()),
    onSuccess: () => {
      setJustification("");
      void queryClient.invalidateQueries();
    },
  });
  return (
    <div className="mt-2 flex flex-wrap items-end gap-3">
      <label className="min-w-64 flex-1 text-xs font-medium">
        Uzasadnienie wymuszenia (co najmniej 20 znaków, trafi do dziennika audytu)
        <Input
          className="mt-1"
          maxLength={4000}
          value={justification}
          onChange={(e) => setJustification(e.target.value)}
        />
      </label>
      <Button
        variant="outline"
        disabled={justification.trim().length < 20 || force.isPending}
        onClick={() => force.mutate()}
      >
        Wymuś mimo testu
      </Button>
      {force.error && (
        <p className="w-full text-sm text-red-700" role="alert">
          {force.error.message}
        </p>
      )}
    </div>
  );
}

function Configs() {
  const configs = useQuery({
    queryKey: ["agent-configs"],
    queryFn: api.agentConfigs,
    refetchInterval: 10_000,
  });
  return (
    <Card className="mb-6">
      <CardHeader>
        <CardTitle>Bramka zmian</CardTitle>
        <CardDescription>
          Każda zmiana modelu, promptu albo zdolności agenta tworzy nową wersję konfiguracji i
          uruchamia szybki test. Wersja wchodzi w życie dopiero po zaliczeniu. Wymuszenie jest
          możliwe, ale wymaga uzasadnienia i zostaje w dzienniku audytu.
        </CardDescription>
      </CardHeader>
      <QueryState
        isPending={configs.isPending}
        error={configs.error}
        empty={configs.data?.length === 0}
        emptyText="Nie ma jeszcze żadnej wersji konfiguracji agenta."
      />
      {configs.data && configs.data.length > 0 && (
        <Table>
          <thead>
            <tr>
              <Th>Utworzona</Th>
              <Th>Model i prompt</Th>
              <Th>Zdolności</Th>
              <Th>Stan</Th>
              <Th>Powód zmiany</Th>
            </tr>
          </thead>
          <tbody>
            {configs.data.map((config) => {
              const state = CONFIG_STATE[config.state] ?? {
                label: config.state,
                variant: "neutral" as const,
              };
              return (
                <tr key={config.id}>
                  <Td className="whitespace-nowrap">
                    {formatDateTime(config.created_at)}
                    <br />
                    <span className="text-xs text-muted-foreground">{config.created_by}</span>
                  </Td>
                  <Td className="font-mono text-xs">
                    {config.model || "szablon"}
                    <br />
                    {config.prompt_version}
                    {config.external_llm && " (zewnętrzny LLM)"}
                  </Td>
                  <Td>v{config.capability_version}</Td>
                  <Td>
                    <Badge variant={state.variant}>{state.label}</Badge>
                    {config.forced_by && (
                      <p className="mt-1 text-xs text-muted-foreground">
                        {config.forced_by}: {config.force_justification}
                      </p>
                    )}
                  </Td>
                  <Td className="text-muted-foreground">
                    {config.reason}
                    {(config.state === "pending_test" || config.state === "rejected") && (
                      <ForceConfig config={config} />
                    )}
                  </Td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

export function AgentTests() {
  const queryClient = useQueryClient();
  const runs = useQuery({
    queryKey: ["agent-tests"],
    queryFn: api.agentTests,
    refetchInterval: 5_000,
  });
  const run = useMutation({
    mutationFn: (suite: "quick" | "full") => api.runAgentTest(suite),
    onSuccess: () => {
      window.setTimeout(() => void queryClient.invalidateQueries(), 2000);
    },
  });

  return (
    <>
      <PageHeader
        title="Test agenta"
        description="Niezależny test bezpieczeństwa agenta. Uruchamia go osobny proces, nie agent: ta sama konfiguracja, narzędzia MCP podmienione na atrapy, kanarki w danych. Wynik jest podpisany i zapisany w dzienniku audytu."
      />
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <Button disabled={run.isPending} onClick={() => run.mutate("quick")}>
          Szybki test
        </Button>
        <Button variant="outline" disabled={run.isPending} onClick={() => run.mutate("full")}>
          Pełny test
        </Button>
        <SignedBy />
        {run.data && (
          <p className="text-sm text-muted-foreground" role="status">
            {run.data.detail}
          </p>
        )}
        {run.error && (
          <p className="text-sm text-red-700" role="alert">
            {run.error.message}
          </p>
        )}
      </div>
      <Configs />
      <h2 className="mb-3 text-base font-semibold">Przebiegi testu</h2>
      <QueryState
        isPending={runs.isPending}
        error={runs.error}
        empty={runs.data?.length === 0}
        emptyText="Test agenta nie był jeszcze uruchamiany."
      />
      {runs.data && runs.data.length > 0 && (
        <Card data-demo="agent-tests">
          <Table>
            <thead>
              <tr>
                <Th>Uruchomiony</Th>
                <Th>Zestaw</Th>
                <Th>Wynik</Th>
                <Th>Kod (krytyczne)</Th>
                <Th>Model</Th>
                <Th>Podpis</Th>
              </tr>
            </thead>
            <tbody>
              {runs.data.map((item) => (
                <tr key={item.id}>
                  <Td className="whitespace-nowrap">
                    <Link className="underline" to={`/agent/test/${item.id}`}>
                      {formatDateTime(item.created_at)}
                    </Link>
                    <br />
                    <span className="text-xs text-muted-foreground">
                      {TRIGGERS[item.trigger] ?? item.trigger}, {item.requested_by}
                    </span>
                  </Td>
                  <Td>{item.suite === "full" ? "pełny" : "szybki"}</Td>
                  <Td>
                    <RunResult run={item} />
                  </Td>
                  <Td>
                    {item.code_passed} / {item.code_passed + item.code_failed} obronionych
                  </Td>
                  <Td>
                    {item.model_passed} / {item.model_passed + item.model_failed} odpartych
                  </Td>
                  <Td>
                    <Signature valid={item.signature_valid} />
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>
      )}
    </>
  );
}

function CaseRow({ result }: { result: AgentCaseResult }) {
  const [open, setOpen] = useState(false);
  const failed = result.verdicts.filter((v) => !v.passed);
  return (
    <>
      <tr>
        <Td>
          <span className="font-medium">{result.title || result.case_id}</span>
          <br />
          <span className="font-mono text-xs text-muted-foreground">{result.case_id}</span>
        </Td>
        <Td>{CATEGORIES[result.category] ?? result.category}</Td>
        <Td>
          {result.code_held ? (
            <Badge variant="ok">obronił</Badge>
          ) : (
            <Badge variant="danger">przeszło</Badge>
          )}
        </Td>
        <Td>
          {result.model_resisted ? (
            <Badge variant="ok">odparł</Badge>
          ) : (
            <Badge variant="warn">uległ</Badge>
          )}
        </Td>
        <Td className="text-xs text-muted-foreground">
          {failed.length > 0
            ? failed.map((v) => `${v.layer}: ${v.detail}`).join("; ")
            : (result.verdicts[0]?.detail ?? "")}
        </Td>
        <Td>
          <Button size="sm" variant="ghost" onClick={() => setOpen(!open)}>
            {open ? "Zwiń" : "Transkrypt"}
          </Button>
        </Td>
      </tr>
      {open && (
        <tr>
          <Td colSpan={6}>
            <pre className="max-h-96 overflow-auto rounded bg-muted p-3 text-xs whitespace-pre-wrap">
              {JSON.stringify({ attempts: result.attempts, ...result.transcript }, null, 2)}
            </pre>
          </Td>
        </tr>
      )}
    </>
  );
}

export function AgentTestDetail() {
  const { id = "" } = useParams();
  const detail = useQuery({
    queryKey: ["agent-test", id],
    queryFn: () => api.agentTest(id),
    refetchInterval: (query) => (query.state.data?.status === "done" ? false : 5_000),
  });
  const data = detail.data;
  return (
    <>
      <PageHeader
        title="Wynik testu agenta"
        description="Dwie oceny: czy model odparł atak (informacyjnie) i czy kod zatrzymał każdą szkodliwą próbę (krytyczne). Test zalicza się, gdy kod obronił wszystkie przypadki."
      />
      <p className="mb-4 text-sm">
        <Link className="underline" to="/agent/test">
          Wróć do listy przebiegów
        </Link>
      </p>
      <QueryState isPending={detail.isPending} error={detail.error} empty={false} emptyText="" />
      {data && (
        <>
          <Card className="mb-6">
            <CardHeader>
              <div className="flex flex-wrap items-center gap-2">
                <CardTitle>
                  {data.suite === "full" ? "Pełny" : "Szybki"} test z {formatDateTime(data.created_at)}
                </CardTitle>
                <RunResult run={data} />
                <Signature valid={data.signature_valid} />
              </div>
              <CardDescription>
                Kod: {data.code_passed} z {data.code_passed + data.code_failed} przypadków
                obronionych. Model: {data.model_passed} z {data.model_passed + data.model_failed}{" "}
                ataków odpartych. Uruchomił: {data.requested_by} (
                {TRIGGERS[data.trigger] ?? data.trigger}).
              </CardDescription>
            </CardHeader>
            {data.result_sha256 && (
              <CardContent>
                <p className="font-mono text-xs break-all text-muted-foreground">
                  SHA-256 wyniku: {data.result_sha256}
                </p>
                {data.public_key && (
                  <details className="mt-2 text-xs">
                    <summary className="cursor-pointer">Klucz publiczny do weryfikacji podpisu</summary>
                    <pre className="mt-1 overflow-auto rounded bg-muted p-2">{data.public_key}</pre>
                  </details>
                )}
              </CardContent>
            )}
          </Card>
          <Card>
            <Table>
              <thead>
                <tr>
                  <Th>Przypadek</Th>
                  <Th>Kategoria</Th>
                  <Th>Kod</Th>
                  <Th>Model</Th>
                  <Th>Werdykt</Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {data.cases.map((result) => (
                  <CaseRow key={result.id} result={result} />
                ))}
              </tbody>
            </Table>
          </Card>
        </>
      )}
    </>
  );
}
