import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { PageHeader, QueryState } from "@/components/Layout";
import { OperatorField } from "@/components/OperatorField";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Table, Td, Th } from "@/components/ui/table";
import { api } from "@/lib/api";
import { useOperator } from "@/lib/operator";

export function ReviewQueue() {
  const queryClient = useQueryClient();
  const [operator, setOperator] = useOperator();
  const [message, setMessage] = useState<string | null>(null);
  const { data, isPending, error } = useQuery({
    queryKey: ["review-queue"],
    queryFn: api.reviewQueue,
  });
  const decide = useMutation({
    mutationFn: ({ id, accept }: { id: string; accept: boolean }) =>
      api.decideReview(id, accept, operator.trim()),
    onSuccess: (result, variables) => {
      setMessage(
        variables.accept
          ? `Dopasowanie potwierdzone. Nowych zagrożeń: ${result.findings_created}.`
          : "Dopasowanie odrzucone. Zagrożenia dla tego produktu nie powstaną.",
      );
      void queryClient.invalidateQueries();
    },
  });
  const ready = operator.trim().length > 0;

  return (
    <>
      <PageHeader
        title="Kolejka weryfikacji"
        description="Dopasowania wykrytego oprogramowania do bazy podatności, których system nie jest pewien. Dopóki człowiek nie potwierdzi dopasowania, nie powstają z niego żadne zagrożenia."
      />
      <Card className="mb-6">
        <CardContent className="flex flex-wrap items-end gap-4 pt-5">
          <OperatorField value={operator} onChange={setOperator} />
          <p className="max-w-xl text-xs text-muted-foreground">
            Decyzja trafia do dziennika audytu razem z imieniem. Pakiety dystrybucji (np. z Debiana)
            często mają poprawki bezpieczeństwa bez zmiany numeru wersji, dlatego system nie zgaduje
            i pyta człowieka.
          </p>
        </CardContent>
      </Card>
      {message && (
        <p className="mb-4 text-sm text-green-800" role="status">
          {message}
        </p>
      )}
      {decide.error && (
        <p className="mb-4 text-sm text-red-700" role="alert">
          {decide.error.message}
        </p>
      )}
      <Card>
        <QueryState
          isPending={isPending}
          error={error}
          empty={data?.length === 0}
          emptyText="Kolejka jest pusta. Wszystkie dopasowania są rozstrzygnięte."
        />
        {data && data.length > 0 && (
          <Table>
            <thead>
              <tr>
                <Th>Zasób</Th>
                <Th>Wykryto</Th>
                <Th>Proponowany produkt (CPE)</Th>
                <Th className="text-right">Pewność</Th>
                <Th>Dlaczego do weryfikacji</Th>
                <Th>Decyzja</Th>
              </tr>
            </thead>
            <tbody>
              {data.map((item) => (
                <tr key={item.id}>
                  <Td className="font-medium">{item.asset.name}</Td>
                  <Td>
                    {item.software.raw_banner ??
                      `${item.software.product} ${item.software.version}`}
                    {item.software.port && (
                      <span className="text-muted-foreground"> · port {item.software.port}</span>
                    )}
                  </Td>
                  <Td className="font-mono text-xs break-all">{item.cpe}</Td>
                  <Td className="text-right tabular-nums">{item.score.toFixed(2)}</Td>
                  <Td className="max-w-sm text-muted-foreground">{item.reason}</Td>
                  <Td>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        disabled={!ready || decide.isPending}
                        onClick={() => decide.mutate({ id: item.id, accept: true })}
                      >
                        Potwierdź
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={!ready || decide.isPending}
                        onClick={() => decide.mutate({ id: item.id, accept: false })}
                      >
                        Odrzuć
                      </Button>
                    </div>
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
