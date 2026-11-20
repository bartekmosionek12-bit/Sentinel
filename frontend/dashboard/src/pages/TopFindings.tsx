import { useQuery } from "@tanstack/react-query";

import { PageHeader, QueryState } from "@shared/components/page";
import { KevBadge, RiskBadge } from "@shared/components/risk";
import { Card } from "@shared/components/ui/card";
import { Table, Td, Th } from "@shared/components/ui/table";
import { api } from "@shared/lib/api";
import { STATUS_LABELS } from "@shared/lib/labels";

export function TopFindings() {
  const findings = useQuery({ queryKey: ["findings", "active"], queryFn: () => api.findings("active") });
  const items = (findings.data?.items ?? []).slice(0, 20);
  return (
    <>
      <PageHeader
        title="Najważniejsze zagrożenia"
        description="Dwadzieścia otwartych zagrożeń o najwyższym ryzyku. Zmiany statusu wprowadza zespół bezpieczeństwa w konsoli operacyjnej."
      />
      <Card>
        <QueryState
          isPending={findings.isPending}
          error={findings.error}
          empty={items.length === 0}
          emptyText="Brak otwartych zagrożeń."
        />
        {items.length > 0 && (
          <Table>
            <thead>
              <tr>
                <Th>Ryzyko</Th>
                <Th>Zasób</Th>
                <Th>Zagrożenie</Th>
                <Th>Status</Th>
                <Th>Odpowiedzialny</Th>
              </tr>
            </thead>
            <tbody>
              {items.map((finding) => (
                <tr key={finding.id}>
                  <Td>
                    <RiskBadge level={finding.risk_level} score={finding.risk_score} />
                  </Td>
                  <Td>{finding.asset.name}</Td>
                  <Td>
                    <span className="flex items-center gap-2">
                      {finding.vulnerability?.cve_id ?? finding.type}
                      {finding.vulnerability?.in_kev && <KevBadge />}
                    </span>
                    <span className="block text-xs text-muted-foreground">{finding.summary}</span>
                  </Td>
                  <Td>{STATUS_LABELS[finding.status]}</Td>
                  <Td>{finding.assignee ?? "nieprzypisane"}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
