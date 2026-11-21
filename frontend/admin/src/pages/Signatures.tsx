import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

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
import { api, type SignatureDefinition } from "@shared/lib/api";
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
}: {
  items: { definition: SignatureDefinition; custom?: { updated_by: string; updated_at: string } }[];
  onEdit?: (definition: SignatureDefinition) => void;
  onDelete?: (id: string) => void;
}) {
  return (
    <Table>
      <thead>
        <tr>
          <Th>Identyfikator</Th>
          <Th>Nazwa</Th>
          <Th>Rodzaj</Th>
          <Th>Dopasowania</Th>
          {(onEdit || onDelete) && <Th>Zmiana</Th>}
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
            {(onEdit || onDelete) && (
              <Td className="whitespace-nowrap">
                {custom && (
                  <div className="mb-1 text-xs text-muted-foreground">
                    {custom.updated_by} · {formatDateTime(custom.updated_at)}
                  </div>
                )}
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
            )}
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function Editor({ text, setText }: { text: string; setText: (value: string) => void }) {
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

      {editable && <Editor text={text} setText={setText} />}

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
              items={list.data.custom.map((row) => ({ definition: row.definition, custom: row }))}
              onEdit={editable ? (d) => setText(JSON.stringify(d, null, 2)) : undefined}
              onDelete={editable ? (id) => remove.mutate(id) : undefined}
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
            <SignatureRows items={list.data.builtin.map((definition) => ({ definition }))} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
