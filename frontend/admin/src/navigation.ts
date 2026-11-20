import {
  ClipboardCheck,
  Crosshair,
  LayoutDashboard,
  ListChecks,
  Network,
  Radar,
  Rss,
  ScrollText,
  Server,
  ShieldAlert,
} from "lucide-react";

import type { NavGroup } from "@shared/components/AppShell";

export const NAV_GROUPS: NavGroup[] = [
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
        summary:
          "Nowe podatności z dzisiaj: te, które nas dotyczą, obok wszystkich opublikowanych.",
      },
      {
        path: "/weryfikacja",
        label: "Kolejka weryfikacji",
        icon: ListChecks,
        summary:
          "Dopasowania oprogramowania do bazy podatności o niskiej pewności, czekające na decyzję człowieka.",
      },
    ],
  },
  {
    title: "Kontrola",
    items: [
      { path: "/skany", label: "Skany", icon: Radar },
      { path: "/zakres", label: "Zakres skanowania", icon: Crosshair },
      { path: "/audyt", label: "Dziennik audytu", icon: ScrollText },
    ],
  },
];
