/** Strony raportów wspólne dla obu konsol: lista i szczegóły. */
import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import { PageHeader, QueryState } from "@shared/components/page";
import { ReportList, ReportView } from "@shared/components/reports";
import { Card } from "@shared/components/ui/card";
import { api } from "@shared/lib/api";

export function ReportsPage({
  basePath,
  actions,
}: {
  basePath: string;
  actions?: ReactNode;
}) {
  const reports = useQuery({ queryKey: ["reports"], queryFn: api.reports });
  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeader
          title="Raporty"
          description="Każdy raport ma dwie warstwy: „W skrócie” prostym językiem i szczegóły techniczne. Światło (czerwone, żółte, zielone) i fakty wylicza system z reguł, nie model językowy."
        />
        {actions}
      </div>
      <Card>
        <QueryState
          isPending={reports.isPending}
          error={reports.error}
          empty={false}
          emptyText=""
        />
        {reports.data && (
          <ReportList
            items={reports.data}
            basePath={basePath}
            emptyText="Nie ma jeszcze raportów. Powstają po ocenie stanu i przy zagrożeniach typu zero-day."
          />
        )}
      </Card>
    </>
  );
}

export function InboxPage({ basePath }: { basePath: string }) {
  const inbox = useQuery({
    queryKey: ["inbox"],
    queryFn: api.inbox,
    refetchInterval: 5_000,
  });
  const unread = inbox.data?.unread ?? 0;
  return (
    <>
      <PageHeader
        title="Skrzynka"
        description={
          unread
            ? `Nieprzeczytane raporty: ${unread}. Zacznij od czerwonych.`
            : "Raporty wysłane do Ciebie przez system. Wszystkie przeczytane."
        }
      />
      <Card>
        <QueryState
          isPending={inbox.isPending}
          error={inbox.error}
          empty={false}
          emptyText=""
        />
        {inbox.data && (
          <ReportList
            items={inbox.data.items}
            basePath={basePath}
            emptyText="Skrzynka jest pusta."
          />
        )}
      </Card>
    </>
  );
}

export function ReportPage({
  backTo,
  actions,
}: {
  backTo: string;
  actions?: (id: string) => ReactNode;
}) {
  const { id = "" } = useParams();
  return (
    <div className="max-w-5xl space-y-4">
      <Link
        to={backTo}
        className="text-sm text-muted-foreground hover:text-foreground"
      >
        ← Wróć do listy
      </Link>
      <ReportView key={id} id={id} actions={actions?.(id)} />
    </div>
  );
}
