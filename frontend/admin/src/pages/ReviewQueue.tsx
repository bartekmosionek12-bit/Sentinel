import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { PageHeader, QueryState } from "@shared/components/page";
import { Button } from "@shared/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@shared/components/ui/card";
import { Table, Td, Th } from "@shared/components/ui/table";
import { api } from "@shared/lib/api";
import { SignedBy } from "@shared/lib/auth";
import { formatDate } from "@shared/lib/utils";

const SIGNAL_METHODS: Record<string, string> = {
  kev_cpe: "przez słownik CPE",
  kev_name: "tylko po nazwie",
};

/** Sygnały bez CPE: KEV wskazuje produkt, ale źródło nie podaje wersji. */
function Signals({ onMessage }: { onMessage: (text: string) => void }) {
  const queryClient = useQueryClient();
  const signals = useQuery({ queryKey: ["signal-queue"], queryFn: api.signalQueue });
  const decide = useMutation({
    mutationFn: ({ id, accept }: { id: string; accept: boolean }) => api.decideSignal(id, accept),
    onSuccess: (result, variables) => {
      onMessage(
        variables.accept
          ? `Sygnał potwierdzony. Nowych zagrożeń: ${result.findings_created}.`
          : "Sygnał odrzucony. Zagrożenie dla tego zasobu nie powstanie.",
      );
      void queryClient.invalidateQueries();
    },
  });
  if (!signals.data || signals.data.length === 0) return null;
  return (
    <Card className="mb-6 border-amber-300">
      <CardHeader>
        <CardTitle>Sygnały bez danych o wersjach ({signals.data.length})</CardTitle>
        <CardDescription>
          Katalog KEV wskazuje aktywnie wykorzystywaną podatność w produkcie, ale baza NVD nie
          podała jeszcze, których wersji dotyczy. System znalazł w inwentarzu produkt o podobnej
          nazwie i nie zgaduje: zagrożenie powstanie tylko po potwierdzeniu. Gdy NVD poda zakres
          wersji, sygnał zastąpi zwykłe dopasowanie.
        </CardDescription>
      </CardHeader>
      {decide.error && (
        <p className="px-5 pb-3 text-sm text-red-700" role="alert">
          {decide.error.message}
        </p>
      )}
      <Table>
        <thead>
          <tr>
            <Th>Podatność (KEV)</Th>
            <Th>Zasób</Th>
            <Th>W inwentarzu</Th>
            <Th className="text-right">Pewność</Th>
            <Th>Dlaczego</Th>
            <Th>Decyzja</Th>
          </tr>
        </thead>
        <tbody>
          {signals.data.map((item) => (
            <tr key={item.id}>
              <Td>
                <span className="font-medium">{item.cve_id}</span>
                <br />
                <span className="text-xs text-muted-foreground">
                  {item.vendor} {item.product}
                  {item.kev_due_date && `, termin CISA ${formatDate(item.kev_due_date)}`}
                </span>
              </Td>
              <Td className="font-medium">{item.asset.name}</Td>
              <Td>
                {item.software.product} {item.software.version}
                {item.software.port && (
                  <span className="text-muted-foreground"> · port {item.software.port}</span>
                )}
              </Td>
              <Td className="text-right tabular-nums">
                {item.score.toFixed(2)}
                <br />
                <span className="text-xs text-muted-foreground">
                  {SIGNAL_METHODS[item.method] ?? item.method}
                </span>
              </Td>
              <Td className="max-w-sm text-muted-foreground">{item.reason}</Td>
              <Td>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    disabled={decide.isPending}
                    onClick={() => decide.mutate({ id: item.id, accept: true })}
                  >
                    Potwierdź
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={decide.isPending}
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
    </Card>
  );
}

export function ReviewQueue() {
  const queryClient = useQueryClient();
  const [message, setMessage] = useState<string | null>(null);
  const { data, isPending, error } = useQuery({
    queryKey: ["review-queue"],
    queryFn: api.reviewQueue,
  });
  const decide = useMutation({
    mutationFn: ({ id, accept }: { id: string; accept: boolean }) =>
      api.decideReview(id, accept),
    onSuccess: (result, variables) => {
      setMessage(
        variables.accept
          ? `Dopasowanie potwierdzone. Nowych zagrożeń: ${result.findings_created}.`
          : "Dopasowanie odrzucone. Zagrożenia dla tego produktu nie powstaną.",
      );
      void queryClient.invalidateQueries();
    },
  });

  return (
    <>
      <PageHeader
        title="Kolejka weryfikacji"
        description="Dopasowania wykrytego oprogramowania do bazy podatności, których system nie jest pewien. Dopóki człowiek nie potwierdzi dopasowania, nie powstają z niego żadne zagrożenia."
      />
      <Card className="mb-6">
        <CardContent className="flex flex-wrap items-end gap-4 pt-5">
          <SignedBy />
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
      <Signals onMessage={setMessage} />
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
                        disabled={decide.isPending}
                        onClick={() => decide.mutate({ id: item.id, accept: true })}
                      >
                        Potwierdź
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={decide.isPending}
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
