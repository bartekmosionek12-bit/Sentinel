/** Szkielet konsoli zespołu IT: czarny pasek systemowy (nazwa, stan, użytkownik) i pasek aplikacji
 *  z menu grup rozwijanym po kliknięciu, jak w konsolach SIEM. Bez menu bocznego. */
import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ShieldCheck, type LucideIcon } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { NavLink, matchPath, useLocation } from "react-router-dom";

import { Badge } from "@shared/components/ui/badge";
import { api } from "@shared/lib/api";
import { UserMenu } from "@shared/lib/auth";
import { useAuth } from "@shared/lib/auth-context";
import { cn } from "@shared/lib/utils";

export interface NavItem {
  path: string;
  label: string;
  icon: LucideIcon;
  /** Etap planu (P0–P12), w którym widok powstaje. Brak = działa już teraz. */
  stage?: number;
  summary?: string;
  /** Aktywny tylko dla dokładnie tej ścieżki (gdy pod nią są inne pozycje menu). */
  end?: boolean;
  /** Uprawnienie potrzebne, żeby pozycja była widoczna (API i tak sprawdza je osobno). */
  permission?: string;
}

export interface NavGroup {
  title: string;
  items: NavItem[];
}

function SystemStatus() {
  const { data, isError, isPending } = useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    refetchInterval: 15_000,
  });
  if (isPending) return <Badge variant="neutral">Łączenie…</Badge>;
  if (isError || !data) return <Badge variant="danger">Brak połączenia z API</Badge>;
  return (
    <div className="flex flex-wrap items-center gap-2">
      {data.demo_mode && (
        <Badge
          variant="warn"
          title="Tryb demo: zasoby pochodzą z demo-lab, a wartości EPSS mogą być przykładowe."
        >
          Dane demonstracyjne
        </Badge>
      )}
      <Badge variant={data.status === "ok" ? "ok" : "warn"}>
        {data.status === "ok" ? "System działa" : "System działa częściowo"}
      </Badge>
    </div>
  );
}

function DemoDataNotice() {
  const { data } = useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 15_000 });
  if (!data?.demo_mode) return null;
  return (
    <p
      role="note"
      className="border-b border-amber-200 bg-amber-50 px-4 py-1 text-xs text-amber-900"
    >
      <strong className="font-semibold">Tryb demo.</strong> Dane z demo-lab; wartości EPSS
      przykładowe.
    </p>
  );
}

function isItemActive(item: NavItem, pathname: string) {
  const end = item.end ?? item.path === "/";
  return Boolean(matchPath({ path: item.path, end }, pathname));
}

/** Grupa menu: przycisk na pasku aplikacji i lista linków pod nim. */
function NavMenu({
  group,
  open,
  onToggle,
}: {
  group: NavGroup;
  open: boolean;
  onToggle: () => void;
}) {
  const { pathname } = useLocation();
  const active = group.items.some((item) => isItemActive(item, pathname));
  const id = `menu-${group.title.replace(/\s+/g, "-").toLowerCase()}`;
  return (
    <li className="relative">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={id}
        onClick={onToggle}
        className={cn(
          "flex h-9 items-center gap-1 border-b-2 border-transparent px-3 text-sm text-sidebar-foreground hover:bg-sidebar-active hover:text-white",
          active && "border-accent font-semibold text-white",
          open && "bg-sidebar-active text-white",
        )}
      >
        {group.title}
        <ChevronDown className="size-3.5 opacity-70" aria-hidden />
      </button>
      <ul
        id={id}
        hidden={!open}
        className="absolute top-full left-0 z-40 min-w-56 border border-border bg-card py-1"
      >
        {group.items.map(({ path, label, icon: Icon, end }) => (
          <li key={path}>
            <NavLink
              to={path}
              end={end ?? path === "/"}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2 border-l-2 border-transparent px-3 py-1.5 text-sm whitespace-nowrap text-foreground hover:bg-muted",
                  isActive && "border-accent bg-muted font-semibold",
                )
              }
            >
              <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
              {label}
            </NavLink>
          </li>
        ))}
      </ul>
    </li>
  );
}

export function AppShell({
  navGroups,
  subtitle,
  footer,
  banner,
  headerExtra,
  children,
}: {
  navGroups: NavGroup[];
  subtitle: string;
  footer: string;
  /** Pilny komunikat nad treścią (np. raport zero-day w skrzynce). */
  banner?: ReactNode;
  /** Dodatkowe elementy w nagłówku . */
  headerExtra?: ReactNode;
  children: ReactNode;
}) {
  const { can } = useAuth();
  const { pathname } = useLocation();
  const [openGroup, setOpenGroup] = useState<string | null>(null);
  const navRef = useRef<HTMLElement>(null);
  const visible = navGroups
    .map((group) => ({
      ...group,
      items: group.items.filter((item) => !item.permission || can(item.permission)),
    }))
    .filter((group) => group.items.length);

  // Menu zamyka się po przejściu na inną stronę, kliknięciu obok i klawiszu Escape.
  useEffect(() => setOpenGroup(null), [pathname]);
  useEffect(() => {
    if (!openGroup) return;
    const onClick = (e: MouseEvent) => {
      if (!navRef.current?.contains(e.target as Node)) setOpenGroup(null);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpenGroup(null);
    };
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [openGroup]);

  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex h-10 items-center justify-between gap-4 bg-sidebar px-4 text-sidebar-foreground">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-sm font-semibold text-white">
            <ShieldCheck className="size-4 text-accent" aria-hidden />
            Sentinel ASI
          </span>
          <span className="hidden border-l border-border pl-3 text-xs text-slate-500 sm:inline">
            {subtitle}
          </span>
        </div>
        <div className="flex items-center gap-3">
          {headerExtra}
          <SystemStatus />
          <UserMenu />
        </div>
      </header>
      <nav
        ref={navRef}
        className="border-b border-border bg-appbar px-2"
        aria-label="Nawigacja główna"
      >
        <ul className="flex flex-wrap items-stretch">
          {visible.map((group) => (
            <NavMenu
              key={group.title}
              group={group}
              open={openGroup === group.title}
              onToggle={() => setOpenGroup((g) => (g === group.title ? null : group.title))}
            />
          ))}
        </ul>
      </nav>
      {banner}
      <DemoDataNotice />
      <main className="min-w-0 flex-1 px-4 pt-4 pb-44 md:px-5">{children}</main>
      {footer && <p className="px-5 pb-4 text-xs text-slate-500">{footer}</p>}
    </div>
  );
}
