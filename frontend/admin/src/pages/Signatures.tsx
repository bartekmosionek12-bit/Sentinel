import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

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
import {
  api,
  type SignatureDefinition,
  type SignatureInspection,
  type SignatureTestResult,
} from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";
import { formatDateTime } from "@shared/lib/utils";

const KIND_LABEL: Record<string, string> = {
  technology: "technologia",
  panel: "panel",
  staging: "staging",
};

const EXAMPLE = `id: moja-aplikacja
name: Moja aplikacja
kind: technology
match:
  - {type: header, name: x-powered-by, pattern: "moja-aplikacja"}
  - {type: title, pattern: "moja aplikacja"}
  - {type: path, path: /version, status: [200], pattern: "\\"version\\""}
`;

type TestRequest = { yaml?: string; id?: string };

/** Wynik testu: które usługi z wybranego przebiegu pasują do sygnatury i dlaczego. */
function SignatureTest({ request }: { request: TestRequest }) {
  const runs = useQuery({
    queryKey: ["discovery-runs"],
    queryFn: api.discoveryRuns,
  });
  const [runId, setRunId] = useState("");
  const finished = (runs.data ?? []).filter((r) =>
    ["done", "stopped", "paused"].includes(r.status),
  );
  const test = useQuery<SignatureTestResult, Error>({
    queryKey: ["signature-test", request, runId],
    queryFn: () => api.testSignature({ ...request, run_id: runId || undefined }),
    retry: false,
  });
  const data = test.data;
  return (
    <Card data-demo="signature-test">
      <CardHeader>
        <CardTitle>Test sygnatury{data ? ` „${data.signature.id}”` : ""}</CardTitle>
        <CardDescription>
          Dopasowanie do wyników zapisanych w przebiegu, bez żadnego ruchu w sieci. Nagłówki,
          ciasteczka, tytuł, hash favicony i kody ścieżek są sprawdzane od razu.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <label className="flex items-center gap-2">
          Przebieg
          <select
            aria-label="Przebieg do testu"
            className="h-9 rounded-md border border-border bg-background px-2"
            value={runId}
            onChange={(e) => setRunId(e.target.value)}
          >
            <option value="">ostatni zakończony</option>
            {finished.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name || r.id.slice(0, 8)} · {formatDateTime(r.created_at)}
              </option>
            ))}
          </select>
        </label>
        {test.isPending && <p className="text-muted-foreground">Sprawdzam…</p>}
        {test.error && <p className="text-red-700">{test.error.message}</p>}
        {data && (
          <>
            <p>
              Sprawdzono {data.services_checked} usług WWW, trafienia: <b>{data.hits.length}</b>.
            </p>
            {data.live_only.length > 0 && (
              <p className="text-xs text-muted-foreground">
                Tych dopasowań nie da się sprawdzić na zapisanych danych, bo treść stron nie jest
                przechowywana: {data.live_only.join(", ")}. Sprawdzi je kolejny przebieg.
              </p>
            )}
            {data.hits.length > 0 && (
              <Table>
                <thead>
                  <tr>
                    <Th>Host</Th>
                    <Th>Usługa</Th>
                    <Th>Dowód</Th>
                  </tr>
                </thead>
                <tbody>
                  {data.hits.map((hit) => (
                    <tr key={`${hit.ip}:${hit.port}:${hit.url}`}>
                      <Td className="font-mono">
                        <Link
                          className="text-primary underline"
                          to={`/discovery/${data.run.id}?host=${hit.ip}`}
                        >
                          {hit.ip}
                        </Link>
                      </Td>
                      <Td className="font-mono text-xs">
                        {hit.url ?? hit.port}
                        {hit.title && (
                          <div className="font-sans text-muted-foreground">{hit.title}</div>
                        )}
                      </Td>
                      <Td>
                        {hit.evidence.join(", ")}
                        {hit.already_flagged && (
                          <Badge variant="neutral" className="ml-2">
                            już w wynikach
                          </Badge>
                        )}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

/** Inspekcja jednej sygnatury: co dokładnie sprawdza, gdzie trafiła i jak w czasie. */
function SignatureInspect({ id, onClose }: { id: string; onClose: () => void }) {
  const query = useQuery<SignatureInspection, Error>({
    queryKey: ["signature-inspect", id],
    queryFn: () => api.inspectSignature(id),
  });
  const d = query.data;
  return (
    <Card data-demo="signature-inspect">
      <CardHeader>
        <CardTitle>Inspekcja sygnatury „{id}”</CardTitle>
        <CardDescription>
          {d
            ? `${d.name} · ${KIND_LABEL[d.kind] ?? d.kind} · ${
                d.source === "builtin"
                  ? "wbudowana (rules/signatures.yaml)"
                  : `własna, ${d.updated_by ?? ""} ${d.updated_at ? formatDateTime(d.updated_at) : ""}`
              }`
            : "Reguły, trafienia w historii przebiegów i dowody."}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        {query.isPending && <p className="text-muted-foreground">Wczytuję…</p>}
        {query.error && <p className="text-red-700">{query.error.message}</p>}
        {d && (
          <>
            {d.description && <p>{d.description}</p>}
            <div>
              <h3 className="mb-1 font-medium">Reguły (wystarczy jedna)</h3>
              <Table>
                <thead>
                  <tr>
                    <Th>Typ</Th>
                    <Th>Co sprawdza</Th>
                    <Th>Ruch sieciowy</Th>
                    <Th>Trafienia w ostatnim przebiegu</Th>
                  </tr>
                </thead>
                <tbody>
                  {d.rules.map((rule, index) => (
                    <tr key={index}>
                      <Td className="font-mono">{rule.type}</Td>
                      <Td>{rule.text}</Td>
                      <Td>
                        {rule.sends_request
                          ? "dodatkowe GET przy skanie"
                          : "nie (odpowiedź już pobrana)"}
                      </Td>
                      <Td>
                        {rule.latest_run_hits === null
                          ? "sprawdza tylko skan (treść nie jest przechowywana)"
                          : `${rule.latest_run_hits} z ${d.services_checked} usług`}
                        {rule.offline_note && (
                          <div className="text-xs text-muted-foreground">{rule.offline_note}</div>
                        )}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
            <div>
              <h3 className="mb-1 font-medium">Trafienia w historii przebiegów</h3>
              {d.history.length === 0 ? (
                <p className="text-muted-foreground">Brak zakończonych przebiegów.</p>
              ) : (
                <div className="flex flex-wrap gap-2" data-demo="signature-history">
                  {d.history.map((h) => (
                    <Link
                      key={h.run_id}
                      to={`/discovery/${h.run_id}`}
                      className="rounded-sm border border-border px-2 py-1 text-xs hover:border-primary"
                    >
                      {formatDateTime(h.created_at)}: <b>{h.hosts}</b> hostów, {h.services} usług
                    </Link>
                  ))}
                </div>
              )}
            </div>
            <div>
              <h3 className="mb-1 font-medium">
                Gdzie trafiła w ostatnim przebiegu
                {d.latest_run ? ` (${d.latest_run.name})` : ""}
              </h3>
              {d.hosts.length === 0 ? (
                <p className="text-muted-foreground">Nigdzie.</p>
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <Th>Host</Th>
                      <Th>Usługa</Th>
                      <Th>Dowód</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.hosts.map((hit) => (
                      <tr key={`${hit.ip}:${hit.port}`}>
                        <Td className="font-mono">
                          <Link
                            className="text-primary underline"
                            to={`/discovery/${d.latest_run?.id}?host=${hit.ip}`}
                          >
                            {hit.ip}
                          </Link>
                        </Td>
                        <Td className="font-mono text-xs">{hit.url ?? hit.port}</Td>
                        <Td>{hit.evidence.join(", ")}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </div>
            <details>
              <summary className="cursor-pointer text-xs text-muted-foreground">Definicja</summary>
              <pre className="mt-1 overflow-x-auto rounded-sm border border-border p-2 font-mono text-xs">
                {JSON.stringify(d.definition, null, 2)}
              </pre>
            </details>
          </>
        )}
        <Button size="sm" variant="ghost" onClick={onClose}>
          Zamknij
        </Button>
      </CardContent>
    </Card>
  );
}

/** Krótki opis dopasowań: typ i to, czego szuka (bez treści żądań, bo ich nie ma). */
function matchSummary(match: SignatureDefinition["match"]): string {
  return match
    .map((m) => {
      const detail = m.path ?? m.name ?? m.pattern ?? m.value;
      return detail === undefined ? String(m.type) : `${String(m.type)}: ${String(detail)}`;
    })
    .join(" · ");
}

function SignatureRows({
  items,
  onEdit,
  onDelete,
  onTest,
  onInspect,
}: {
  items: {
    definition: SignatureDefinition;
    custom?: { updated_by: string; updated_at: string };
  }[];
  onEdit?: (definition: SignatureDefinition) => void;
  onDelete?: (id: string) => void;
  onTest: (id: string) => void;
  onInspect: (id: string) => void;
}) {
  return (
    <Table>
      <thead>
        <tr>
          <Th>Identyfikator</Th>
          <Th>Nazwa</Th>
          <Th>Rodzaj</Th>
          <Th>Dopasowania</Th>
          <Th>Akcje</Th>
        </tr>
      </thead>
      <tbody>
        {items.map(({ definition, custom }) => (
          <tr key={definition.id}>
            <Td className="font-mono">{definition.id}</Td>
            <Td>
              {definition.name ?? definition.id}
              {definition.description && (
                <div className="text-xs text-muted-foreground">{definition.description}</div>
              )}
            </Td>
            <Td>
              <Badge variant={definition.kind === "technology" ? "info" : "warn"}>
                {KIND_LABEL[definition.kind] ?? definition.kind}
              </Badge>
            </Td>
            <Td className="font-mono text-xs">{matchSummary(definition.match)}</Td>
            {
              <Td className="whitespace-nowrap">
                {custom && (
                  <div className="mb-1 text-xs text-muted-foreground">
                    {custom.updated_by} · {formatDateTime(custom.updated_at)}
                  </div>
                )}
                <Button
                  size="sm"
                  variant="outline"
                  aria-label={`Testuj ${definition.id}`}
                  onClick={() => onTest(definition.id)}
                >
                  Testuj
                </Button>{" "}
                <Button
                  size="sm"
                  variant="outline"
                  aria-label={`Inspekcja ${definition.id}`}
                  onClick={() => onInspect(definition.id)}
                >
                  Inspekcja
                </Button>{" "}
                {onEdit && (
                  <Button size="sm" variant="outline" onClick={() => onEdit(definition)}>
                    Edytuj
                  </Button>
                )}{" "}
                {onDelete && (
                  <Button size="sm" variant="ghost" onClick={() => onDelete(definition.id)}>
                    Usuń
                  </Button>
                )}
              </Td>
            }
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function Editor({
  text,
  setText,
  onTest,
}: {
  text: string;
  setText: (value: string) => void;
  onTest: () => void;
}) {
  const queryClient = useQueryClient();
  const check = useMutation({ mutationFn: () => api.checkSignature(text) });
  const save = useMutation({
    mutationFn: async () => {
      const { definition } = await api.checkSignature(text);
      return api.saveSignature(definition.id, text);
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["signatures"] }),
  });
  const error = save.error ?? check.error;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Nowa albo zmieniona sygnatura</CardTitle>
        <CardDescription>
          Jedna sygnatura w YAML, w tym samym kształcie co w rules/signatures.yaml. Działa od
          następnego przebiegu discovery.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <textarea
          aria-label="Sygnatura w YAML"
          className="h-56 w-full rounded-md border border-border bg-background p-3 font-mono text-sm"
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            check.reset();
            save.reset();
          }}
        />
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => check.mutate()} disabled={!text.trim()}>
            Sprawdź
          </Button>
          <Button onClick={() => save.mutate()} disabled={!text.trim() || save.isPending}>
            Zapisz
          </Button>
          <Button variant="ghost" onClick={onTest} disabled={!text.trim()}>
            Testuj na przebiegu
          </Button>
        </div>
        {error && <p className="text-sm text-red-700">{error.message}</p>}
        {check.data && !save.data && !error && (
          <p className="text-sm text-green-700">
            Sygnatura „{check.data.definition.id}” jest poprawna.
          </p>
        )}
        {save.data && <p className="text-sm text-green-700">Zapisano „{save.data.id}”.</p>}
      </CardContent>
    </Card>
  );
}

export function Signatures() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [text, setText] = useState(EXAMPLE);
  const [testing, setTesting] = useState<TestRequest | null>(null);
  const [inspecting, setInspecting] = useState<string | null>(null);
  const list = useQuery({ queryKey: ["signatures"], queryFn: api.signatures });
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteSignature(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["signatures"] }),
  });
  const editable = can("scan:run");
  const rules = list.data?.rules;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Sygnatury detekcyjne"
        description="Własne reguły rozpoznawania technologii, paneli i środowisk staging."
      />
      <Card>
        <CardHeader>
          <CardTitle>Zasady</CardTitle>
          <CardDescription>
            Sygnatura mówi tylko, czego szukać w odpowiedziach, które fingerprinter i tak pobiera
            metodą GET. Nie ma w niej metody, treści żądania, poświadczeń ani parametrów.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm">
          {rules && (
            <ul className="list-disc space-y-1 pl-5">
              <li>Rodzaje: {rules.kinds.join(", ")}.</li>
              <li>Typy dopasowań: {rules.match_types.join(", ")}. Wystarczy jedno dopasowanie.</li>
              <li>
                Ścieżki (typ path): jedno GET bez logowania, najwyżej {rules.max_paths} ścieżek
                łącznie. Warto dodać wzorzec treści, bo aplikacje SPA dają 200 na każdą ścieżkę.
              </li>
            </ul>
          )}
        </CardContent>
      </Card>

      {editable && (
        <Editor text={text} setText={setText} onTest={() => setTesting({ yaml: text })} />
      )}

      {inspecting && <SignatureInspect id={inspecting} onClose={() => setInspecting(null)} />}
      {testing && <SignatureTest request={testing} />}

      <Card>
        <CardHeader>
          <CardTitle>Własne sygnatury</CardTitle>
        </CardHeader>
        <CardContent>
          <QueryState
            isPending={list.isPending}
            error={list.error}
            empty={(list.data?.custom.length ?? 0) === 0}
            emptyText="Brak własnych sygnatur."
          />
          {remove.error && <p className="text-sm text-red-700">{remove.error.message}</p>}
          {list.data && list.data.custom.length > 0 && (
            <SignatureRows
              items={list.data.custom.map((row) => ({
                definition: row.definition,
                custom: row,
              }))}
              onEdit={editable ? (d) => setText(JSON.stringify(d, null, 2)) : undefined}
              onDelete={editable ? (id) => remove.mutate(id) : undefined}
              onTest={(id) => setTesting({ id })}
              onInspect={setInspecting}
            />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Wbudowane sygnatury</CardTitle>
          <CardDescription>Z pliku rules/signatures.yaml, tylko do odczytu.</CardDescription>
        </CardHeader>
        <CardContent>
          {list.data && (
            <SignatureRows
              items={list.data.builtin.map((definition) => ({ definition }))}
              onTest={(id) => setTesting({ id })}
              onInspect={setInspecting}
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
