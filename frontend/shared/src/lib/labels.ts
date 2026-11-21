import type { FindingStatus } from "@shared/lib/api";

export const STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Otwarte",
  acknowledged: "Przyjęte do wiadomości",
  in_progress: "W trakcie naprawy",
  resolved: "Rozwiązane",
  accepted_risk: "Ryzyko zaakceptowane",
  false_positive: "Fałszywy alarm",
};

/** Typy urządzeń (Etap 6, ARCHITECTURE §7.1). */
export const DEVICE_TYPE_LABELS: Record<string, string> = {
  host: "Host",
  server: "Serwer",
  workstation: "Stacja robocza",
  laptop: "Laptop",
  network: "Urządzenie sieciowe",
  printer: "Drukarka",
  iot: "Urządzenie IoT",
  cloud: "Zasób w chmurze",
  ai_system: "System AI",
};

export const DEVICE_STATUS_LABELS: Record<string, string> = {
  active: "Znane",
  shadow: "Nieznane",
  missing: "Nie odpowiada",
  retired: "Wycofane",
};
