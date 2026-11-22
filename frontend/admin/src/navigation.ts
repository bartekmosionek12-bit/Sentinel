import {
  Bot,
  CalendarClock,
  Crosshair,
  GitCompareArrows,
  FileText,
  FlaskConical,
  LayoutDashboard,
  ListChecks,
  Radar,
  Rss,
  ScrollText,
  Server,
  ShieldAlert,
  Fingerprint,
  Layers3,
  ShieldCheck,
  UserCog,
} from "lucide-react";

import type { NavGroup } from "@shared/components/AppShell";

export const NAV_GROUPS: NavGroup[] = [
  {
    title: "Przegląd",
    items: [
      { path: "/", label: "Pulpit", icon: LayoutDashboard },
      {
        path: "/raporty",
        label: "Raporty",
        icon: FileText,
        permission: "reports:read",
        summary: "Raporty dwuwarstwowe: „W skrócie” dla kierownictwa i szczegóły techniczne dla zespołu IT.",
      },
    ],
  },
  {
    title: "Discovery",
    items: [
      {
        path: "/discovery",
        label: "Przebiegi discovery",
        icon: Radar,
        end: true,
        permission: "scan:read",
      },
      {
        path: "/discovery/porownanie",
        label: "Porównanie i stany",
        icon: GitCompareArrows,
        permission: "scan:read",
      },
      {
        path: "/discovery/harmonogram",
        label: "Harmonogram",
        icon: CalendarClock,
        permission: "scan:read",
      },
      {
        path: "/discovery/sygnatury",
        label: "Sygnatury detekcyjne",
        icon: Fingerprint,
        permission: "scan:read",
      },
    ],
  },
  {
    title: "Podatności (moduł dodatkowy)",
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
    title: "Skanowanie podatności",
    items: [
      {
        path: "/warstwy",
        label: "Trzy warstwy",
        icon: Layers3,
        permission: "findings:read",
        summary:
          "Warstwa 1: deterministyczny skan, warstwa 2: analiza LLM, warstwa 3: agent AI. Każdą uruchamia się osobno i jawnie.",
      },
    ],
  },
  {
    title: "Kontrola",
    items: [
      {
        path: "/skany",
        label: "Skany podatności",
        icon: Radar,
        summary:
          "Moduł dodatkowy: skany L1–L3 do dopasowania CVE. Discovery dużych sieci jest w sekcji Discovery.",
      },
      { path: "/zakres", label: "Zakres skanowania", icon: Crosshair },
      { path: "/agent", label: "Agent AI", icon: Bot, end: true },
      { path: "/agent/test", label: "Test agenta", icon: FlaskConical },
      { path: "/audyt", label: "Dziennik audytu", icon: ScrollText, permission: "audit:read" },
      {
        path: "/iam",
        label: "IAM",
        icon: ShieldCheck,
        permission: "iam:read",
        summary:
          "Human i non-human identity osobno: role, delegacje trzech warstw skanowania i zdolności agenta AI.",
      },
      { path: "/role", label: "Role i użytkownicy", icon: UserCog, permission: "iam:read" },
    ],
  },
];
