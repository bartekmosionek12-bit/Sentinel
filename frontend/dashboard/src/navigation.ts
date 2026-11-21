import {
  ClipboardCheck,
  FileText,
  HelpCircle,
  Home,
  Inbox,
  Monitor,
  ShieldAlert,
  Users,
} from "lucide-react";

import type { NavGroup } from "@shared/components/AppShell";

/** Dashboard menedżera: tylko odczyt, bez adresów i danych technicznych (redakcja w API). */
export const NAV_GROUPS: NavGroup[] = [
  {
    title: "Przegląd",
    items: [
      { path: "/", label: "Strona główna", icon: Home },
      { path: "/zagrozenia", label: "Najważniejsze zagrożenia", icon: ShieldAlert },
      { path: "/urzadzenia", label: "Urządzenia", icon: Monitor },
      { path: "/nieznane", label: "Nieznane i niepotwierdzone", icon: HelpCircle },
      { path: "/ludzie", label: "Ludzie i urządzenia", icon: Users },
    ],
  },
  {
    title: "Dla zarządu",
    items: [
      { path: "/skrzynka", label: "Skrzynka", icon: Inbox },
      { path: "/raporty", label: "Raporty", icon: FileText },
      {
        path: "/zgodnosc",
        label: "Zgodność",
        icon: ClipboardCheck,
        stage: 7,
        summary: "Stan wymagań KSC (NIS2), RODO art. 32, ISO 27001 i CIS, z linkiem do przepisu.",
      },
    ],
  },
];
