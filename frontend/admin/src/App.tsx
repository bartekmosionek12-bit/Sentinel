import { useQuery } from "@tanstack/react-query";
import { Navigate, Route, Routes } from "react-router-dom";

import { NAV_GROUPS } from "@/navigation";
import { Agent } from "@/pages/Agent";
import { AgentTestDetail, AgentTests } from "@/pages/AgentTests";
import { Assets } from "@/pages/Assets";
import { AuditLog } from "@/pages/AuditLog";
import { Dashboard } from "@/pages/Dashboard";
import { Findings } from "@/pages/Findings";
import { ReportDetail, Reports } from "@/pages/Reports";
import { ReviewQueue } from "@/pages/ReviewQueue";
import { Scans } from "@/pages/Scans";
import { Scope } from "@/pages/Scope";
import { ThreatFeed } from "@/pages/ThreatFeed";
import { AppShell } from "@shared/components/AppShell";
import { Planned } from "@shared/components/Planned";
import { api, ApiError } from "@shared/lib/api";
import { AccessDenied } from "@shared/lib/auth";
import { useAuth } from "@shared/lib/auth-context";

const planned = NAV_GROUPS.flatMap((group) => group.items).filter((item) => item.stage);

/** Konsola operacyjna jest dla administratora zalogowanego z TOTP. O wejściu decyduje API
 *  (`console:admin`); odmowa trafia do dziennika audytu, a każda operacja i tak ma osobne
 *  uprawnienie sprawdzane przy wywołaniu. */
export function App() {
  const { me } = useAuth();
  const access = useQuery({
    queryKey: ["console-access", "admin"],
    queryFn: api.adminConsoleAccess,
    retry: false,
    staleTime: Infinity,
  });
  if (access.isPending) {
    return <p className="p-8 text-sm text-muted-foreground">Sprawdzanie uprawnień…</p>;
  }
  if (access.error) {
    if (!(access.error instanceof ApiError) || access.error.status !== 403) {
      return (
        <p className="p-8 text-sm text-red-700">
          Nie udało się sprawdzić uprawnień: {access.error.message}
        </p>
      );
    }
    const admin = me?.roles.includes("admin");
    return (
      <AccessDenied title="Brak dostępu do konsoli operacyjnej">
        {admin ? (
          <p>
            Operacje administratora wymagają logowania z drugim składnikiem (TOTP). Wyloguj się
            i zaloguj ponownie do konsoli operacyjnej.
          </p>
        ) : (
          <p>
            Ta konsola jest przeznaczona dla administratorów bezpieczeństwa. Próba dostępu
            została zapisana w dzienniku audytu. Przegląd stanu bezpieczeństwa znajdziesz w{" "}
            <a className="underline" href="/dashboard/">
              dashboardzie
            </a>
            .
          </p>
        )}
      </AccessDenied>
    );
  }
  return (
    <AppShell
      navGroups={NAV_GROUPS}
      subtitle="Konsola operacyjna"
      footer="Decyzje podejmuje kod. Model językowy tylko tłumaczy."
    >
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/raporty" element={<Reports />} />
        <Route path="/raporty/:id" element={<ReportDetail />} />
        <Route path="/zasoby" element={<Assets />} />
        <Route path="/zagrozenia" element={<Findings />} />
        <Route path="/feed" element={<ThreatFeed />} />
        <Route path="/weryfikacja" element={<ReviewQueue />} />
        <Route path="/skany" element={<Scans />} />
        <Route path="/zakres" element={<Scope />} />
        <Route path="/agent" element={<Agent />} />
        <Route path="/agent/test" element={<AgentTests />} />
        <Route path="/agent/test/:id" element={<AgentTestDetail />} />
        <Route path="/audyt" element={<AuditLog />} />
        {planned.map((item) => (
          <Route key={item.path} path={item.path} element={<Planned item={item} />} />
        ))}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  );
}
