import type { FindingStatus } from "@/lib/api";

export const STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Otwarte",
  acknowledged: "Przyjęte do wiadomości",
  in_progress: "W trakcie naprawy",
  resolved: "Rozwiązane",
  accepted_risk: "Ryzyko zaakceptowane",
  false_positive: "Fałszywy alarm",
};
