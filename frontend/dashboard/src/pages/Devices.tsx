import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";

import { DeviceTable } from "@shared/components/devices";
import { FreshnessNote } from "@shared/components/freshness";
import { PageHeader } from "@shared/components/page";
import { Card } from "@shared/components/ui/card";
import { api } from "@shared/lib/api";

export function Devices() {
  const [params] = useSearchParams();
  const unitId = params.get("dzial") ?? undefined;
  const overview = useQuery({ queryKey: ["org-overview"], queryFn: api.orgOverview });
  const unit = overview.data?.units.find((u) => u.id === unitId);
  return (
    <>
      <PageHeader
        title={unit ? `Urządzenia: ${unit.name}` : "Urządzenia"}
        description="Wszystkie urządzenia organizacji z działem, właścicielem i stanem zagrożeń. Dane łączą skany, CMDB, AD, MDM i DHCP. Kliknij urządzenie, żeby otworzyć jego kartę."
      />
      {unit && (
        <p className="mb-4 text-sm">
          <Link className="underline" to="/urzadzenia">
            Pokaż wszystkie działy
          </Link>
        </p>
      )}
      <div className="mb-4">
        <FreshnessNote scope={unitId ? "unit" : "organization"} scopeRef={unitId ?? null} />
      </div>
      <Card>
        <DeviceTable
          key={unitId ?? "all"}
          filter={unitId ? { unit: unitId } : {}}
          basePath="/urzadzenia"
          showUnitFilter={!unit}
        />
      </Card>
    </>
  );
}

export function UnknownDevices() {
  return (
    <>
      <PageHeader
        title="Nieznane i niepotwierdzone"
        description="Urządzenia widziane w sieci (skan albo DHCP), których nie ma w CMDB, AD ani MDM. To mogą być prywatne sprzęty, zapomniane serwery albo shadow IT. Potwierdza je zespół bezpieczeństwa w konsoli operacyjnej; widzimy tylko to, co odpowiada w skanowanych sieciach albo dostało adres z DHCP."
      />
      <Card>
        <DeviceTable
          filter={{ unknown: true }}
          basePath="/urzadzenia"
          csvName="nieznane-urzadzenia.csv"
          showUnitFilter={false}
          emptyText="Brak nieznanych urządzeń w skanowanych sieciach."
        />
      </Card>
    </>
  );
}
