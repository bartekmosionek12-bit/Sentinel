import { Navigate, Route, Routes } from "react-router-dom";

import { NAV_GROUPS } from "@/navigation";
import { DashboardSentek } from "@/sentek";
import { TourButton } from "@/tour";
import { DeviceCard } from "@/pages/DeviceCard";
import { Devices, UnknownDevices } from "@/pages/Devices";
import { Home } from "@/pages/Home";
import { OrgMap } from "@/pages/OrgMap";
import { People } from "@/pages/People";
import { TopFindings } from "@/pages/TopFindings";
import { AppShell } from "@shared/components/AppShell";
import { SentekToggle } from "@shared/components/assistant";
import { InboxPage, ReportPage, ReportsPage } from "@shared/components/ReportPages";
import { ZeroDayBanner } from "@shared/components/reports";
import { Planned } from "@shared/components/Planned";
import { AccessDenied } from "@shared/lib/auth";
import { useAuth } from "@shared/lib/auth-context";

const planned = NAV_GROUPS.flatMap((group) => group.items).filter((item) => item.stage);

export function App() {
  const { can } = useAuth();
  if (!can("findings:read")) {
    return (
      <AccessDenied title="Brak dostępu do dashboardu">
        <p>Twoje konto nie ma roli, która daje wgląd w stan bezpieczeństwa.</p>
      </AccessDenied>
    );
  }
  return (
    <AppShell
      navGroups={NAV_GROUPS}
      subtitle="Dashboard menedżera"
      footer="Widok tylko do odczytu. Dane techniczne są ukryte."
      banner={can("reports:read") ? <ZeroDayBanner basePath="/raporty" /> : null}
      headerExtra={
        <>
          <SentekToggle />
          <TourButton />
        </>
      }
    >
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/zagrozenia" element={<TopFindings />} />
        <Route path="/urzadzenia" element={<Devices />} />
        <Route path="/urzadzenia/:id" element={<DeviceCard />} />
        <Route path="/mapa" element={<OrgMap />} />
        <Route path="/nieznane" element={<UnknownDevices />} />
        <Route path="/ludzie" element={<People />} />
        <Route path="/skrzynka" element={<InboxPage basePath="/raporty" />} />
        <Route path="/raporty" element={<ReportsPage basePath="/raporty" />} />
        <Route path="/raporty/:id" element={<ReportPage backTo="/skrzynka" />} />
        {planned.map((item) => (
          <Route key={item.path} path={item.path} element={<Planned item={item} />} />
        ))}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      <DashboardSentek />
    </AppShell>
  );
}
