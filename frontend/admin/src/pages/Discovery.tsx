import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileUp, Play, Search, Square, Upload } from "lucide-react";
import { useEffect, useState, type ChangeEvent } from "react";
import { Link, useNavigate } from "react-router-dom";

import { PageHeader, QueryState } from "@shared/components/page";
import { Badge } from "@shared/components/ui/badge";
import { Button } from "@shared/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@shared/components/ui/card";
import { Input } from "@shared/components/ui/input";
import { Table, Td, Th } from "@shared/components/ui/table";
import { api, type DiscoveryRun, type DiscoverySettings } from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";
import { formatDateTime } from "@shared/lib/utils";

import { formatSeconds, RUN_STATUS } from "@/labels";

/** Cele z pliku CSV (kolumna target/ip/cidr/domena albo pierwsza kolumna), JSON albo listy. */
function targetsFromFile(name: string, text: string): string {
  const trimmed = text.trim();
  if (name.endsWith(".json") || trimmed.startsWith("[") || trimmed.startsWith("{")) {
    const data: unknown = JSON.parse(trimmed);
    const items = Array.isArray(data) ? data : ((data as { targets?: unknown[] }).targets ?? []);
    return items
      .map((item) =>
        typeof item === "string"
          ? item
          : String(
              (item as Record<string, unknown>).target ??
                (item as Record<string, unknown>).ip ??
                "",
            ),
      )
      .filter(Boolean)
      .join("\n");
  }
  const lines = trimmed.split(/\r?\n/);
  const header = (lines[0] ?? "").toLowerCase().split(/[;,]/);
  const column = header.findIndex((h) =>
    ["target", "cel", "ip", "cidr", "domena", "domain"].includes(h.trim()),
  );
  const body = column >= 0 ? lines.slice(1) : lines;
  return body
    .map((line) => line.split(/[;,]/)[Math.max(column, 0)]?.trim() ?? "")
    .filter(Boolean)
    .join("\n");
}

export function RunStatus({ run }: { run: DiscoveryRun }) {
  const item = RUN_STATUS[run.status] ?? {
    label: run.status,
    variant: "neutral" as const,
  };
  return <Badge variant={item.variant}>{item.label}</Badge>;
}

export function Progress({ value }: { value: number }) {
  return (
    <div
      className="h-2.5 w-full rounded-sm bg-muted"
      role="progressbar"
      aria-valuenow={Math.round(value * 100)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className="h-2.5 rounded-sm bg-primary"
        style={{ width: `${Math.round(value * 100)}%` }}
      />
    </div>
  );
}

function NumberField({
  label,
  hint,
  value,
  max,
  min = 1,
  onChange,
}: {
  label: string;
  hint: string;
  value: number;
  max: number;
  min?: number;
  onChange: (value: number) => void;
}) {
  return (
    <label className="text-sm font-medium">
      {label}
      <Input
        className="mt-1"
        type="number"
        min={min}
        max={max}
        value={value}
        onChange={(e) => onChange(Math.min(max, Math.max(min, Number(e.target.value) || min)))}
      />
      <span className="mt-1 block text-xs font-normal text-muted-foreground">{hint}</span>
    </label>
  );
}

function TargetForm() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const config = useQuery({
    queryKey: ["discovery-config"],
    queryFn: api.discoveryConfig,
  });
  const [text, setText] = useState("");
  const [name, setName] = useState("");
  const [endAt, setEndAt] = useState("");
  const [settings, setSettings] = useState<Partial<DiscoverySettings>>({});
  const [fileError, setFileError] = useState<string | null>(null);
  useEffect(() => {
    if (config.data) setSettings((s) => ({ ...config.data.defaults, ...s }));
  }, [config.data]);
  const preview = useMutation({ mutationFn: () => api.previewTargets(text) });
  const start = useMutation({
    mutationFn: () =>
      api.startDiscovery({
        text,
        name,
        settings: {
          workers: settings.workers,
          max_rate: settings.max_rate,
          timing: settings.timing,
        },
        end_at: endAt ? new Date(endAt).toISOString() : null,
      }),
    onSuccess: (run) => {
      void queryClient.invalidateQueries({ queryKey: ["discovery-runs"] });
      navigate(`/discovery/${run.id}`);
    },
  });
  const limits = config.data?.limits ?? {};

  const onFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      setText(targetsFromFile(file.name, await file.text()));
      setFileError(null);
      preview.reset();
    } catch {
      setFileError(
        "Nie udało się odczytać pliku. Obsługiwane: CSV, JSON, lista po jednym celu w wierszu.",
      );
    }
    event.target.value = "";
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Nowy przebieg</CardTitle>
        <CardDescription>
          Adresy IP, zakresy CIDR i domeny, po jednym w wierszu, albo plik CSV/JSON. Przed startem
          sprawdzamy składnię i zgodność z zatwierdzonym zakresem.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
          <label className="text-sm font-medium">
            Cele
            <textarea
              data-demo="targets"
              className="mt-1 h-40 w-full rounded-md border border-border bg-background p-3 font-mono text-sm"
              placeholder={"10.20.0.0/18\n172.30.99.0/24\nportal.example.test"}
              value={text}
              onChange={(e) => {
                setText(e.target.value);
                preview.reset();
              }}
            />
          </label>
          <div className="space-y-4">
            <label className="text-sm font-medium">
              Nazwa przebiegu
              <Input
                className="mt-1"
                placeholder="np. Sieć kampusowa, listopad"
                value={name}
                maxLength={200}
                onChange={(e) => setName(e.target.value)}
              />
            </label>
            <label className="block text-sm font-medium">
              Zakończ najpóźniej (opcjonalnie)
              <Input
                type="datetime-local"
                aria-label="Koniec przebiegu"
                className="mt-1"
                value={endAt}
                onChange={(e) => setEndAt(e.target.value)}
              />
              <span className="mt-1 block text-xs font-normal text-muted-foreground">
                Po tej chwili skan kończy rozpoczęte paczki, zapisuje resztę celów i czeka na
                „Wznów”.
              </span>
            </label>
            <label className="flex cursor-pointer items-center gap-2 rounded-md border border-dashed border-border p-3 text-sm hover:bg-muted">
              <FileUp className="size-5 text-primary" aria-hidden />
              Wczytaj cele z pliku (CSV, JSON, TXT)
              <input
                data-demo="targets-file"
                type="file"
                accept=".csv,.json,.txt"
                className="sr-only"
                onChange={(e) => void onFile(e)}
              />
            </label>
            {fileError && <p className="text-sm text-red-700">{fileError}</p>}
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-3">
          <NumberField
            label="Równoległe workery"
            hint={`Procesy nmap naraz (limit ${limits.workers ?? 16})`}
            value={settings.workers ?? 4}
            max={limits.workers ?? 16}
            onChange={(workers) => setSettings((s) => ({ ...s, workers }))}
          />
          <NumberField
            label="Pakiety na sekundę"
            hint={`Na jeden worker, --max-rate (limit ${limits.max_rate ?? 2000})`}
            value={settings.max_rate ?? 300}
            max={limits.max_rate ?? 2000}
            onChange={(max_rate) => setSettings((s) => ({ ...s, max_rate }))}
          />
          <NumberField
            label="Szablon czasowy nmap"
            hint="0–3; T4 i T5 są zablokowane"
            value={settings.timing ?? 3}
            min={0}
            max={3}
            onChange={(timing) => setSettings((s) => ({ ...s, timing }))}
          />
        </div>

        <div className="flex flex-wrap gap-3">
          <Button
            data-demo="preview-btn"
            variant="outline"
            disabled={!text.trim() || preview.isPending}
            onClick={() => preview.mutate()}
          >
            <Search className="size-4" aria-hidden />
            Sprawdź cele
          </Button>
          <Button
            data-demo="start-run"
            disabled={!preview.data?.ok || start.isPending}
            onClick={() => start.mutate()}
          >
            <Play className="size-4" aria-hidden />
            Uruchom skan
          </Button>
        </div>
        {start.error && <p className="text-sm text-red-700">{start.error.message}</p>}

        {preview.data && (
          <div className="rounded-md border border-border p-4" data-demo="preview">
            <div className="mb-3 flex flex-wrap items-center gap-3">
              <Badge variant={preview.data.ok ? "ok" : "danger"}>
                {preview.data.ok ? "Gotowe do skanu" : "Popraw cele"}
              </Badge>
              <span className="text-lg font-semibold tabular-nums">
                {preview.data.addresses.toLocaleString("pl-PL")} adresów
              </span>
              <span className="text-sm text-muted-foreground">
                {preview.data.networks} zakresów, {preview.data.domains} domen
              </span>
            </div>
            {preview.data.errors.map((error) => (
              <p key={error} className="text-sm text-red-700">
                {error}
              </p>
            ))}
            <Table>
              <thead>
                <tr>
                  <Th>Cel</Th>
                  <Th>Adresów</Th>
                  <Th>Zakres</Th>
                </tr>
              </thead>
              <tbody>
                {preview.data.rows.slice(0, 12).map((row) => (
                  <tr key={row.target}>
                    <Td className="font-mono">{row.target}</Td>
                    <Td className="tabular-nums">{row.addresses.toLocaleString("pl-PL")}</Td>
                    <Td>
                      <Badge variant={row.allowed ? "ok" : "danger"}>
                        {row.allowed ? "W zakresie" : `Poza zakresem: ${row.reason}`}
                      </Badge>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ImportCard() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const upload = useMutation({
    mutationFn: async (file: File) => api.importResults(await file.text(), file.name),
    onSuccess: (run) => {
      void queryClient.invalidateQueries({ queryKey: ["discovery-runs"] });
      navigate(`/discovery/${run.id}`);
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Import wyników</CardTitle>
        <CardDescription>
          Wyniki z innych narzędzi: JSON, CSV (kolumna ip) albo nmap XML. Zapisujemy je jako osobny
          przebieg, więc można je porównać ze skanami.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <label className="flex cursor-pointer items-center gap-2 rounded-md border border-dashed border-border p-3 text-sm hover:bg-muted">
          <Upload className="size-5 text-primary" aria-hidden />
          Wybierz plik wyników
          <input
            data-demo="import-file"
            type="file"
            accept=".json,.csv,.xml"
            className="sr-only"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) upload.mutate(file);
              e.target.value = "";
            }}
          />
        </label>
        {upload.isPending && <p className="mt-2 text-sm">Importowanie…</p>}
        {upload.error && <p className="mt-2 text-sm text-red-700">{upload.error.message}</p>}
      </CardContent>
    </Card>
  );
}

export function RunsTable({ runs, compact = false }: { runs: DiscoveryRun[]; compact?: boolean }) {
  const queryClient = useQueryClient();
  const stop = useMutation({
    mutationFn: api.stopDiscovery,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["discovery-runs"] }),
  });
  const { can } = useAuth();
  return (
    <Table>
      <thead>
        <tr>
          <Th>Przebieg</Th>
          <Th>Status</Th>
          <Th className="w-48">Postęp</Th>
          <Th>Hosty</Th>
          {!compact && <Th>Paczki</Th>}
          <Th>Czas</Th>
          <Th>ETA</Th>
          {!compact && <Th />}
        </tr>
      </thead>
      <tbody>
        {runs.map((run) => (
          <tr key={run.id}>
            <Td>
              <Link className="font-medium text-primary underline" to={`/discovery/${run.id}`}>
                {run.name || "Bez nazwy"}
              </Link>
              <p className="text-xs text-muted-foreground">
                {formatDateTime(run.created_at)} · {run.source === "import" ? "import" : "skan"} ·{" "}
                {run.addresses_total.toLocaleString("pl-PL")} adresów
              </p>
            </Td>
            <Td>
              <RunStatus run={run} />
            </Td>
            <Td>
              <Progress value={run.progress} />
              <span className="text-xs tabular-nums text-muted-foreground">
                {Math.round(run.progress * 100)}%
              </span>
            </Td>
            <Td className="text-base font-semibold tabular-nums">{run.hosts_up}</Td>
            {!compact && <Td className="tabular-nums">{run.batches_done}</Td>}
            <Td className="tabular-nums">{formatSeconds(run.duration_seconds)}</Td>
            <Td className="tabular-nums">
              {run.status === "running" ? formatSeconds(run.eta_seconds) : "–"}
            </Td>
            {!compact && (
              <Td>
                {(run.status === "running" || run.status === "queued") && can("scan:run") && (
                  <Button size="sm" variant="outline" onClick={() => stop.mutate(run.id)}>
                    <Square className="size-3.5" aria-hidden />
                    Zatrzymaj
                  </Button>
                )}
              </Td>
            )}
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export function Discovery() {
  const { can } = useAuth();
  const runs = useQuery({
    queryKey: ["discovery-runs"],
    queryFn: api.discoveryRuns,
    refetchInterval: 3000,
  });
  return (
    <>
      <PageHeader
        title="Discovery"
        description="Wykrywanie hostów i usług w dużych zakresach: paczki o adaptacyjnym rozmiarze, równoległe workery, limit tempa i prognoza zakończenia."
      />
      {can("scan:run") && (
        <div className="mb-6 grid gap-6 xl:grid-cols-[2fr_1fr]">
          <TargetForm />
          {can("inventory:write") && <ImportCard />}
        </div>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Przebiegi</CardTitle>
          <CardDescription>
            Odświeżane co 3 sekundy. Wyniki zapisujemy po każdej paczce, więc widać je w trakcie.{" "}
            <Link className="text-primary underline" to="/discovery/porownanie">
              Porównaj dwa przebiegi
            </Link>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <QueryState
            isPending={runs.isPending}
            error={runs.error}
            empty={runs.data?.length === 0}
            emptyText="Nie było jeszcze żadnego przebiegu."
          />
          {runs.data && runs.data.length > 0 && <RunsTable runs={runs.data} />}
        </CardContent>
      </Card>
    </>
  );
}
