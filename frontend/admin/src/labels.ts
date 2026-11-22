type Variant = "ok" | "warn" | "danger" | "neutral" | "info";

export const RUN_STATUS: Record<string, { label: string; variant: Variant }> = {
  queued: { label: "W kolejce", variant: "neutral" },
  running: { label: "W toku", variant: "info" },
  stopping: { label: "Zatrzymywanie", variant: "warn" },
  stopped: { label: "Zatrzymany", variant: "warn" },
  paused: { label: "Wstrzymany (koniec okna)", variant: "warn" },
  done: { label: "Zakończony", variant: "ok" },
  failed: { label: "Błąd", variant: "danger" },
};

export const HOST_STATE: Record<string, { label: string; variant: Variant; hint: string }> = {
  active: {
    label: "Aktywny",
    variant: "ok",
    hint: "Odpowiada w ostatnich przebiegach.",
  },
  unstable: {
    label: "Niestabilny",
    variant: "warn",
    hint: "Odpowiedzi przeplatają się z ich brakiem.",
  },
  unconfirmed: {
    label: "Niepotwierdzony",
    variant: "info",
    hint: "Nie odpowiedział ostatnio, ale za mało przebiegów, by uznać go za nieaktywny.",
  },
  inactive: {
    label: "Nieaktywny",
    variant: "danger",
    hint: "Brak odpowiedzi w N kolejnych przebiegach.",
  },
};

export const CONFIDENCE_VARIANT: Record<string, Variant> = {
  wysoka: "danger",
  średnia: "warn",
  niska: "neutral",
};

export function formatSeconds(value: number | null | undefined): string {
  if (value === null || value === undefined) return "–";
  const s = Math.max(0, Math.round(value));
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ${s % 60} s`;
  return `${Math.floor(m / 60)} h ${m % 60} min`;
}
