import { Navigate, Route, Routes } from "react-router-dom";

import { Layout } from "@/components/Layout";
import { NAV_GROUPS } from "@/navigation";
import { Assets } from "@/pages/Assets";
import { AuditLog } from "@/pages/AuditLog";
import { Dashboard } from "@/pages/Dashboard";
import { Planned } from "@/pages/Planned";
import { Scope } from "@/pages/Scope";

const planned = NAV_GROUPS.flatMap((group) => group.items).filter((item) => item.stage);

export function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/zasoby" element={<Assets />} />
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
