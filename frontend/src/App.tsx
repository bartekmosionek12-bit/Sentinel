import { Navigate, Route, Routes } from "react-router-dom";

import { Layout } from "@/components/Layout";
import { NAV_GROUPS } from "@/navigation";
import { Assets } from "@/pages/Assets";
import { AuditLog } from "@/pages/AuditLog";
import { Dashboard } from "@/pages/Dashboard";
import { Findings } from "@/pages/Findings";
import { Planned } from "@/pages/Planned";
import { ReviewQueue } from "@/pages/ReviewQueue";
import { Scans } from "@/pages/Scans";
import { Scope } from "@/pages/Scope";
import { ThreatFeed } from "@/pages/ThreatFeed";

const planned = NAV_GROUPS.flatMap((group) => group.items).filter((item) => item.stage);

export function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/zasoby" element={<Assets />} />
        <Route path="/zagrozenia" element={<Findings />} />
        <Route path="/feed" element={<ThreatFeed />} />
        <Route path="/weryfikacja" element={<ReviewQueue />} />
        <Route path="/skany" element={<Scans />} />
        <Route path="/zakres" element={<Scope />} />
        <Route path="/audyt" element={<AuditLog />} />
        {planned.map((item) => (
          <Route key={item.path} path={item.path} element={<Planned item={item} />} />
        ))}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
