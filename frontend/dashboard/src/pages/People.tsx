import { useQuery } from "@tanstack/react-query";

import { PseudonymToggle } from "@shared/components/devices";
import { PageHeader, QueryState } from "@shared/components/page";
import { Badge } from "@shared/components/ui/badge";
import { Card } from "@shared/components/ui/card";
import { Table, Td, Th } from "@shared/components/ui/table";
import { api } from "@shared/lib/api";
import { usePseudonyms } from "@shared/lib/privacy";

export function People() {
  const pseudonyms = usePseudonyms();
  const people = useQuery({
    queryKey: ["people", pseudonyms],
    queryFn: () => api.people(pseudonyms),
  });
  const rows = people.data ?? [];
  return (
    <>
      <PageHeader
        title="Ludzie i urządzenia"
        description="Kto odpowiada za urządzenia i kto ich używa. Przechowujemy tylko przypisanie urządzenia do osoby z katalogu organizacji, bez aktywności pracowników. Każdy podgląd nazwisk zapisuje się w dzienniku audytu."
      />
      <Card>
        <div className="flex border-b border-border p-3">
          <div className="ml-auto">
            <PseudonymToggle />
          </div>
        </div>
        <QueryState
          isPending={people.isPending}
          error={people.error}
          empty={rows.length === 0}
          emptyText="Brak osób. Organizacja nie została jeszcze zsynchronizowana."
        />
        {rows.length > 0 && (
          <Table>
            <thead>
              <tr>
                <Th>Osoba</Th>
                <Th>Stanowisko</Th>
                <Th>Dział</Th>
                <Th>Urządzenia</Th>
                <Th>Stan</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((p) => (
                <tr key={p.id}>
                  <Td className="font-medium">{p.display_name}</Td>
                  <Td>{p.job_title ?? <span className="text-muted-foreground">ukryte</span>}</Td>
                  <Td>{p.unit ?? "brak"}</Td>
                  <Td className="tabular-nums">{p.devices}</Td>
                  <Td>
                    {p.active ? (
                      <Badge variant="ok">Pracuje</Badge>
                    ) : (
                      <Badge variant="warn" title="Urządzenia do przejęcia przez dział">
                        Już nie pracuje
                      </Badge>
                    )}
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
