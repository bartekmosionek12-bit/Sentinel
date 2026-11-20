import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { PageHeader, QueryState } from "@/components/Layout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/utils";

const PAGE_SIZE = 50;

const ACTION_LABELS: Record<string, string> = {
  scope_allowed: "Zakres: dozwolone",
  scope_denied: "Zakres: zablokowane",
  scope_awaiting_approval: "Zakres: czeka na zgodę",
  scope_rate_limited: "Zakres: limit szybkości",
  asset_created: "Dodano zasób",
};

function actionVariant(action: string): "ok" | "danger" | "warn" | "info" {
  if (action === "scope_allowed") return "ok";
  if (action === "scope_denied") return "danger";
  if (action.startsWith("scope_")) return "warn";
  return "info";
}

export function AuditLog() {
  const [page, setPage] = useState(0);
  const { data, isPending, error } = useQuery({
    queryKey: ["audit-log", page],
    queryFn: () => api.auditLog(PAGE_SIZE, page * PAGE_SIZE),
    placeholderData: keepPreviousData,
  });
  const chain = useQuery({ queryKey: ["audit-chain"], queryFn: api.auditChain });
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  return (
    <>
      <PageHeader
        title="Dziennik audytu"
        description="Każda akcja systemu: co, kiedy, kto lub która reguła, dlaczego i na podstawie jakich danych. Dziennik jest tylko do dopisywania, a wpisy są połączone łańcuchem skrótów."
      />
      <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
        {chain.data &&
          (chain.data.ok ? (
            <Badge variant="ok">Łańcuch spójny, {chain.data.entries} wpisów</Badge>
          ) : (
            <Badge variant="danger">
              Niespójność przy wpisie nr {chain.data.broken_at_id}: {chain.data.detail}
            </Badge>
          ))}
        <Button variant="outline" size="sm" onClick={() => void chain.refetch()}>
          Sprawdź ponownie
        </Button>
      </div>
      <Card>
        <QueryState
          isPending={isPending}
          error={error}
          empty={data?.items.length === 0}
          emptyText="Dziennik jest pusty. Wpisy pojawią się po pierwszej akcji systemu."
        />
        {data && data.items.length > 0 && (
          <Table>
            <thead>
              <tr>
                <Th>Nr</Th>
                <Th>Kiedy</Th>
                <Th>Akcja</Th>
                <Th>Kto lub reguła</Th>
                <Th>Obiekt</Th>
                <Th>Dlaczego</Th>
                <Th>Dane wejściowe</Th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((entry) => (
                <tr key={entry.id}>
                  <Td className="tabular-nums">{entry.id}</Td>
                  <Td className="whitespace-nowrap">{formatDateTime(entry.ts)}</Td>
                  <Td>
                    <Badge variant={actionVariant(entry.action)}>
                      {ACTION_LABELS[entry.action] ?? entry.action}
                    </Badge>
                  </Td>
                  <Td className="font-mono text-xs break-all">{entry.actor}</Td>
                  <Td className="font-mono text-xs break-all">{entry.object_id ?? "–"}</Td>
                  <Td className="min-w-48">{entry.reason}</Td>
                  <Td>
                    <details>
                      <summary className="cursor-pointer text-xs text-primary">Pokaż</summary>
                      <pre className="mt-2 max-w-md overflow-x-auto rounded bg-muted p-2 text-xs">
                        {JSON.stringify(entry.inputs, null, 2)}
                      </pre>
                      <p className="mt-1 font-mono text-[10px] break-all text-muted-foreground">
                        skrót: {entry.hash}
                      </p>
                    </details>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      {data && data.total > PAGE_SIZE && (
        <div className="mt-4 flex items-center gap-3 text-sm">
          <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage(page - 1)}>
            Nowsze
          </Button>
          <span className="text-muted-foreground">
            Strona {page + 1} z {pages}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={page + 1 >= pages}
            onClick={() => setPage(page + 1)}
          >
            Starsze
          </Button>
        </div>
      )}
    </>
  );
}
