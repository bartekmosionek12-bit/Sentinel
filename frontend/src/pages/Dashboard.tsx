import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { PageHeader } from "@/components/Layout";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";

function Stat({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <Card>
      <CardHeader>
        <CardDescription>{label}</CardDescription>
        <p className="text-3xl font-semibold tabular-nums">{value}</p>
      </CardHeader>
      <CardContent>
        <p className="text-xs text-muted-foreground">{hint}</p>
      </CardContent>
    </Card>
  );
}

export function Dashboard() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const assets = useQuery({ queryKey: ["assets"], queryFn: api.assets });
  const chain = useQuery({ queryKey: ["audit-chain"], queryFn: api.auditChain });
  const scope = useQuery({ queryKey: ["scope"], queryFn: api.scope });

  const scopeSize = scope.data
    ? scope.data.allowed_cidrs.length + scope.data.allowed_domains.length
    : undefined;

  return (
    <>
      <PageHeader
        title="Pulpit"
        description="Stan systemu w skrócie. Wskaźnik ryzyka, trend i najważniejsze zagrożenia pojawią się tutaj po podłączeniu skanów i feedów."
      />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat
          label="Zasoby w inwentarzu"
          value={assets.data ? String(assets.data.total) : "–"}
          hint="Hosty, domeny, adresy IP, usługi i aplikacje"
        />
        <Stat
          label="Wpisy w dzienniku audytu"
          value={chain.data ? String(chain.data.entries) : "–"}
          hint={
            chain.data
              ? chain.data.ok
                ? "Łańcuch skrótów jest spójny"
                : "Uwaga: wykryto niespójność łańcucha"
              : "Sprawdzanie spójności…"
          }
        />
        <Stat
          label="Reguły zakresu"
          value={scopeSize === undefined ? "–" : String(scopeSize)}
          hint={
            scopeSize === 0
              ? "Zakres pusty: żadne skanowanie nie jest dozwolone"
              : "Dozwolone domeny i zakresy adresów"
          }
        />
        <Stat
          label="Wersja"
          value={health.data?.version ?? "–"}
          hint={health.data?.demo_mode ? "Tryb demo włączony" : "Tryb demo wyłączony"}
        />
      </div>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Usługi</CardTitle>
          <CardDescription>Składniki, od których zależy działanie systemu.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Badge variant={health.data?.database ? "ok" : "danger"}>
            Baza danych: {health.data?.database ? "działa" : "niedostępna"}
          </Badge>
          <Badge variant={health.data?.redis ? "ok" : "danger"}>
            Kolejka zadań: {health.data?.redis ? "działa" : "niedostępna"}
          </Badge>
        </CardContent>
      </Card>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Od czego zacząć</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p>
            1. Ustaw <Link className="text-primary underline" to="/zakres">zakres skanowania</Link>.
            Bez niego system niczego nie dotknie.
          </p>
          <p>
            2. Dodaj pierwsze <Link className="text-primary underline" to="/zasoby">zasoby</Link>{" "}
            albo poczekaj na wynik odkrywania.
          </p>
          <p>
            3. Każdą decyzję systemu znajdziesz w{" "}
            <Link className="text-primary underline" to="/audyt">dzienniku audytu</Link>.
          </p>
        </CardContent>
      </Card>
    </>
  );
}
