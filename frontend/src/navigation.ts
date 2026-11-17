import {
  ClipboardCheck,
  Crosshair,
  LayoutDashboard,
  ListChecks,
  Network,
  Rss,
  ScrollText,
  Server,
  ShieldAlert,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  path: string;
  label: string;
  icon: LucideIcon;
  /** Etap planu, w którym widok dostaje dane. Brak = działa już teraz. */
  stage?: number;
  summary?: string;
}

export const NAV_GROUPS: { title: string; items: NavItem[] }[] = [
  {
    title: "Przegląd",
    items: [
      { path: "/", label: "Pulpit", icon: LayoutDashboard },
      {
        path: "/mapa",
        label: "Mapa powierzchni ataku",
        icon: Network,
        stage: 5,
        summary: "Interaktywny graf zasobów i relacji między nimi, kolorowany poziomem ryzyka.",
      },
    ],
  },
  {
    title: "Inwentarz i ryzyko",
    items: [
      { path: "/zasoby", label: "Zasoby", icon: Server },
      {
        path: "/zagrozenia",
        label: "Zagrożenia",
        icon: ShieldAlert,
        stage: 2,
        summary:
          "Lista zagrożeń przypisanych do konkretnych zasobów, ze statusem, właścicielem i rozbiciem oceny ryzyka.",
      },
      {
        path: "/zgodnosc",
        label: "Zgodność",
        icon: ClipboardCheck,
        stage: 4,
        summary: "Wynik zgodności dla CIS, NIS2 i ISO 27001 z listą luk i instrukcją naprawy.",
      },
      {
        path: "/feed",
        label: "Feed zagrożeń",
        icon: Rss,
        stage: 2,
        summary: "Nowe podatności z dzisiaj: te, które nas dotyczą, obok wszystkich opublikowanych.",
      },
      {
        path: "/weryfikacja",
        label: "Kolejka weryfikacji",
        icon: ListChecks,
        stage: 2,
        summary:
          "Dopasowania oprogramowania do bazy podatności o niskiej pewności, czekające na decyzję człowieka.",
      },
    ],
  },
  {
    title: "Kontrola",
    items: [
      { path: "/zakres", label: "Zakres skanowania", icon: Crosshair },
      { path: "/audyt", label: "Dziennik audytu", icon: ScrollText },
    ],
  },
];

