import { useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import { DeviceStatus, PseudonymToggle } from "@shared/components/devices";
import { PageHeader, QueryState } from "@shared/components/page";
import { KevBadge, RiskBadge } from "@shared/components/risk";
import { Card, CardContent, CardHeader, CardTitle } from "@shared/components/ui/card";
import { api, type OrgPerson } from "@shared/lib/api";
import { DEVICE_TYPE_LABELS } from "@shared/lib/labels";
import { usePseudonyms } from "@shared/lib/privacy";
import { formatDateTime } from "@shared/lib/utils";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-3 gap-3 py-1.5 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="col-span-2">{children}</dd>
    </div>
  );
}

function Person({ person }: { person: OrgPerson }) {
  return (
    <span className="block">
      {person.display_name}
      {person.job_title && <span className="text-muted-foreground">, {person.job_title}</span>}
      {!person.active && <span className="text-amber-800"> (już nie pracuje: do przejęcia)</span>}
    </span>
  );
}

const EXPOSURE = { internet: "dostępne z internetu", internal: "tylko w sieci wewnętrznej" };

export function DeviceCard() {
  const { id = "" } = useParams();
  const pseudonyms = usePseudonyms();
  const device = useQuery({
    queryKey: ["device", id, pseudonyms],
    queryFn: () => api.device(id, pseudonyms),
  });
  const findings = useQuery({ queryKey: ["device-findings", id], queryFn: () => api.deviceFindings(id) });
  const d = device.data;
  return (
    <>
      <Link to="/urzadzenia" className="mb-4 inline-flex items-center gap-1 text-sm underline">
        <ArrowLeft className="size-4" aria-hidden /> Wszystkie urządzenia
      </Link>
      <QueryState isPending={device.isPending} error={device.error} empty={false} emptyText="" />
      {d && (
        <>
          <PageHeader
            title={d.name}
            description={`${DEVICE_TYPE_LABELS[d.type] ?? d.type}, ${EXPOSURE[d.exposure]}, ważność ${d.criticality} z 5.`}
          />
          {d.status === "shadow" && (
            <p
              role="note"
              className="mb-6 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900"
            >
              <strong>Nieznane urządzenie.</strong> Widzieliśmy je w sieci ({d.sources.join(", ")}),
              ale nie ma go w CMDB, AD ani MDM. Ustal z działem IT, czyje jest; jeśli jest
              potrzebne, zespół bezpieczeństwa doda je do inwentarza.
            </p>
          )}
          <div className="grid gap-6 xl:grid-cols-2">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle>Kto i gdzie</CardTitle>
                <PseudonymToggle />
              </CardHeader>
              <CardContent>
                <dl>
                  <Row label="Stan">
                    <DeviceStatus device={d} />
                  </Row>
                  <Row label="Dział">{d.unit ?? "nieprzypisane"}</Row>
                  <Row label="Właściciel">
                    {d.owners.length ? d.owners.map((p) => <Person key={p.id} person={p} />) : "brak"}
                  </Row>
                  <Row label="Użytkownik">
                    {d.users.length ? d.users.map((p) => <Person key={p.id} person={p} />) : "brak"}
                  </Row>
                  <Row label="Lokalizacja">{d.location ?? "nieznana"}</Row>
                  <Row label="Segment sieci">{d.segment ?? "nieznany"}</Row>
                </dl>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Skąd o nim wiemy</CardTitle>
              </CardHeader>
              <CardContent>
                <dl>
                  <Row label="Źródła">{d.sources.join(", ") || "brak"}</Row>
                  <Row label="W CMDB lub katalogu">{d.in_cmdb ? "tak" : "nie"}</Row>
                  <Row label="Pierwszy raz">{formatDateTime(d.first_seen)}</Row>
                  <Row label="Ostatni skan">
                    {d.last_scan ? formatDateTime(d.last_scan) : "jeszcze nie skanowane"}
                  </Row>
                </dl>
              </CardContent>
            </Card>
          </div>
          <Card className="mt-6">
            <CardHeader>
              <CardTitle>Otwarte zagrożenia ({d.open_findings})</CardTitle>
            </CardHeader>
            <CardContent>
              <QueryState
                isPending={findings.isPending}
                error={findings.error}
                empty={(findings.data?.items.length ?? 0) === 0}
                emptyText="Brak otwartych zagrożeń na tym urządzeniu."
              />
              <ul className="space-y-3">
                {(findings.data?.items ?? []).map((f) => (
                  <li key={f.id} className="flex items-start gap-3">
                    <RiskBadge level={f.risk_level} score={f.risk_score} />
                    <span className="text-sm">
                      <span className="flex items-center gap-2 font-medium">
                        {f.vulnerability?.cve_id ??
                          (f.type === "exposure" ? "Nieznane urządzenie w sieci" : f.type)}
                        {f.vulnerability?.in_kev && <KevBadge />}
                      </span>
                      <span className="block text-xs text-muted-foreground">{f.summary}</span>
                    </span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        </>
      )}
    </>
  );
}
