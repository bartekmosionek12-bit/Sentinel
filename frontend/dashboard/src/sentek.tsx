import { useNavigate } from "react-router-dom";

import { runTour } from "@/tour-steps";
import { SentekAssistant } from "@shared/components/assistant";
import { useAuth } from "@shared/lib/auth-context";

/** Sentek w konsoli menedżera; intencja „tour” uruchamia ten sam samouczek co przycisk. */
export function DashboardSentek() {
  const navigate = useNavigate();
  const { me } = useAuth();
  const user = me?.username;
  return (
    <SentekAssistant
      onTour={user ? () => runTour(navigate, user) : undefined}
    />
  );
}
