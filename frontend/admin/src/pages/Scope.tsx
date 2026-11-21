import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { PageHeader } from "@shared/components/page";
import { Badge } from "@shared/components/ui/badge";
import { Button } from "@shared/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@shared/components/ui/card";
import { Input, Select } from "@shared/components/ui/input";
import { api } from "@shared/lib/api";
import { formatDateTime } from "@shared/lib/utils";

function ScopeList({ title, items, empty }: { title: string; items: string[]; empty: string }) {
  return (
    <div>
      <p className="mb-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">
        {title}
      </p>
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{empty}</p>
      ) : (
        <ul className="flex flex-wrap gap-2">
          {items.map((item) => (
            <li key={item}>
              <Badge className="font-mono">{item}</Badge>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

const LEVELS: { value: 1 | 2 | 3; label: string }[] = [
  { value: 1, label: "L1: pasywny i lekki" },
  { value: 2, label: "L2: inwazyjny (wymaga zgody admina)" },
  { value: 3, label: "L3: red team systemów AI (wymaga zgody admina)" },
];

export function Scope() {
  const queryClient = useQueryClient();
  const { data: scope, error } = useQuery({ queryKey: ["scope"], queryFn: api.scope });
  const [target, setTarget] = useState("");
  const [level, setLevel] = useState<1 | 2 | 3>(1);
  const check = useMutation({
    mutationFn: () => api.checkScope(target.trim(), level),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["audit-log"] });
      void queryClient.invalidateQueries({ queryKey: ["audit-chain"] });
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    check.mutate();
  }

  const isEmpty = scope && scope.allowed_cidrs.length + scope.allowed_domains.length === 0;

  return (
    <>
      <PageHeader
        title="Zakres skanowania"
        description="System dotyka wyłącznie celów z tej listy. Każde aktywne działanie przechodzi przez scope_guard, a każda decyzja trafia do dziennika audytu. Zakres zmienia się w pliku konfiguracyjnym, nie w przeglądarce."
      />

      {error && <p className="mb-4 text-sm text-red-700">Nie udało się wczytać zakresu.</p>}
      {isEmpty && (
        <p className="mb-4 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
          Zakres jest pusty, więc żadne skanowanie nie jest dozwolone. To ustawienie domyślne.
        </p>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Dozwolone</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <ScopeList title="Domeny" items={scope?.allowed_domains ?? []} empty="Brak" />
            <ScopeList title="Zakresy adresów" items={scope?.allowed_cidrs ?? []} empty="Brak" />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Wykluczone</CardTitle>
            <CardDescription>Wykluczenia mają pierwszeństwo przed listą dozwolonych.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <ScopeList title="Domeny" items={scope?.denied_domains ?? []} empty="Brak" />
            <ScopeList title="Zakresy adresów" items={scope?.denied_cidrs ?? []} empty="Brak" />
          </CardContent>
        </Card>
      </div>

      {scope && (
        <Card className="mt-6">
          <CardHeader>
            <CardTitle>Limity i tryb demo</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p>
              Domyślny limit: <strong>{scope.default_rate_per_minute}</strong> akcji na minutę na
              jeden cel.
            </p>
            <p>Tempo skanu: do <strong>{scope.scan_packets_per_second}</strong> pakietów/s, <strong>{scope.scan_workers}</strong> równoległe workery, profil nmap T3.</p>
            <p>Host nieaktywny po <strong>{scope.missing_after_runs}</strong> kolejnych przebiegach bez odpowiedzi.</p>
            <p>
              Tryb demo:{" "}
              <Badge variant={scope.demo_mode ? "warn" : "neutral"}>
                {scope.demo_mode ? "włączony" : "wyłączony"}
              </Badge>
            </p>
            {scope.demo_mode && (
              <p className="text-muted-foreground">
                Zgoda automatyczna na skany inwazyjne obejmuje tylko sieć laboratorium{" "}
                <span className="font-mono">{scope.demo_lab_cidr}</span>
                {scope.demo_approval_expires_at
                  ? ` i wygasa ${formatDateTime(scope.demo_approval_expires_at)}.`
                  : ", ale nie została jeszcze udzielona."}
              </p>
            )}
          </CardContent>
        </Card>
      )}

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Sprawdź cel</CardTitle>
          <CardDescription>
            Podgląd decyzji bez skanowania. Sprawdzenie zostanie zapisane w dzienniku audytu.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="grid items-end gap-3 md:grid-cols-[1fr_16rem_auto]">
            <label className="text-xs font-medium">
              Adres IP lub nazwa hosta
              <Input
                className="mt-1 font-mono"
                required
                maxLength={255}
                placeholder="np. 10.10.0.5"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </label>
            <label className="text-xs font-medium">
              Poziom inwazyjności
              <Select
                className="mt-1"
                value={level}
                onChange={(e) => setLevel(Number(e.target.value) as 1 | 2 | 3)}
              >
                {LEVELS.map((item) => (
                  <option key={item.value} value={item.value}>
                    {item.label}
                  </option>
                ))}
              </Select>
            </label>
            <Button type="submit" disabled={check.isPending}>
              Sprawdź
            </Button>
          </form>
          {check.error && (
            <p className="mt-3 text-sm text-red-700" role="alert">
              {check.error.message}
            </p>
          )}
          {check.data && (
            <div className="mt-4 flex flex-wrap items-center gap-3 text-sm" role="status">
              <Badge variant={check.data.allowed ? "ok" : "danger"}>
                {check.data.allowed ? "Dozwolone" : "Zablokowane"}
              </Badge>
              <span className="font-mono">{check.data.target}</span>
              <span className="text-muted-foreground">{check.data.reason}</span>
            </div>
          )}
        </CardContent>
      </Card>
    </>
  );
}
