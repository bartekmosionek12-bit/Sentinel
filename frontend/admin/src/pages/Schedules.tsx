import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

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
import { api, type DiscoverySchedule, type DiscoveryScheduleInput } from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";
import { formatDateTime } from "@shared/lib/utils";

import { RUN_STATUS } from "@/labels";

const DAYS = ["pon", "wt", "śr", "czw", "pt", "sob", "nd"];
const FREQUENCIES = [
  { minutes: 60, label: "co godzinę" },
  { minutes: 360, label: "co 6 godzin" },
  { minutes: 720, label: "co 12 godzin" },
  { minutes: 1440, label: "codziennie" },
  { minutes: 10080, label: "co tydzień" },
];

const EMPTY: DiscoveryScheduleInput = {
  name: "",
  text: "",
  interval_minutes: 1440,
  window_start: "22:00",
  window_end: "06:00",
  days: [0, 1, 2, 3, 4, 5, 6],
  timezone: "Europe/Warsaw",
  enabled: true,
};

function frequencyLabel(minutes: number): string {
  return (
    FREQUENCIES.find((f) => f.minutes === minutes)?.label ??
    (minutes % 60 === 0 ? `co ${minutes / 60} h` : `co ${minutes} min`)
  );
}

function daysLabel(days: number[]): string {
  if (days.length === 7) return "codziennie";
  if (days.join() === "0,1,2,3,4") return "pon–pt";
  return days.map((d) => DAYS[d]).join(", ");
}

function ScheduleForm({
  initial,
  editingId,
  onDone,
}: {
  initial: DiscoveryScheduleInput;
  editingId: string | null;
  onDone: () => void;
}) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState(initial);
  const save = useMutation({
    mutationFn: () => api.saveDiscoverySchedule(form, editingId ?? undefined),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["discovery-schedules"] });
      onDone();
    },
  });
  const set = <K extends keyof DiscoveryScheduleInput>(key: K, value: DiscoveryScheduleInput[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  return (
    <Card>
      <CardHeader>
        <CardTitle>{editingId ? "Zmiana harmonogramu" : "Nowy harmonogram"}</CardTitle>
        <CardDescription>
          Przebieg startuje tylko w oknie czasowym. Jeśli nie zdąży przed końcem okna, kończy
          rozpoczęte paczki, zapisuje resztę celów i wznawia ją w kolejnym oknie.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
          <label className="text-sm font-medium">
            Cele
            <textarea
              aria-label="Cele harmonogramu"
              className="mt-1 h-32 w-full rounded-md border border-border bg-background p-3 font-mono text-sm"
              placeholder={"10.20.0.0/18\n172.30.99.0/24"}
              value={form.text}
              onChange={(e) => set("text", e.target.value)}
            />
          </label>
          <div className="space-y-3">
            <label className="block text-sm font-medium">
              Nazwa
              <Input
                className="mt-1"
                placeholder="np. Nocny skan kampusu"
                value={form.name}
                maxLength={200}
                onChange={(e) => set("name", e.target.value)}
              />
            </label>
            <label className="block text-sm font-medium">
              Częstotliwość
              <select
                aria-label="Częstotliwość"
                className="mt-1 h-9 w-full rounded-md border border-border bg-background px-2 text-sm"
                value={form.interval_minutes}
                onChange={(e) => set("interval_minutes", Number(e.target.value))}
              >
                {FREQUENCIES.map((f) => (
                  <option key={f.minutes} value={f.minutes}>
                    {f.label}
                  </option>
                ))}
              </select>
            </label>
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-3">
          <label className="text-sm font-medium">
            Okno od
            <Input
              type="time"
              aria-label="Początek okna"
              className="mt-1"
              value={form.window_start}
              onChange={(e) => set("window_start", e.target.value)}
            />
          </label>
          <label className="text-sm font-medium">
            Okno do
            <Input
              type="time"
              aria-label="Koniec okna"
              className="mt-1"
              value={form.window_end}
              onChange={(e) => set("window_end", e.target.value)}
            />
          </label>
          <label className="text-sm font-medium">
            Strefa czasowa
            <Input
              className="mt-1"
              value={form.timezone}
              onChange={(e) => set("timezone", e.target.value)}
            />
          </label>
        </div>
        <p className="text-xs text-muted-foreground">
          Koniec wcześniejszy niż początek oznacza okno przez północ (np. 22:00–06:00).
        </p>
        <fieldset className="flex flex-wrap items-center gap-3 text-sm">
          <legend className="mb-1 text-sm font-medium">Dni rozpoczęcia okna</legend>
          {DAYS.map((label, day) => (
            <label key={label} className="flex items-center gap-1">
              <input
                type="checkbox"
                checked={form.days.includes(day)}
                onChange={(e) =>
                  set(
                    "days",
                    e.target.checked
                      ? [...form.days, day].sort()
                      : form.days.filter((d) => d !== day),
                  )
                }
              />
              {label}
            </label>
          ))}
          <label className="ml-4 flex items-center gap-1">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => set("enabled", e.target.checked)}
            />
            włączony
          </label>
        </fieldset>
        <div className="flex gap-2">
          <Button
            onClick={() => save.mutate()}
            disabled={!form.name.trim() || !form.text.trim() || save.isPending}
          >
            {editingId ? "Zapisz zmiany" : "Dodaj harmonogram"}
          </Button>
          {editingId && (
            <Button variant="ghost" onClick={onDone}>
              Anuluj
            </Button>
          )}
        </div>
        {save.error && <p className="text-sm text-red-700">{save.error.message}</p>}
      </CardContent>
    </Card>
  );
}

function nextLabel(s: DiscoverySchedule): string {
  if (!s.enabled) return "wyłączony";
  if (s.resume_pending && s.in_window) return "wznowienie w tej chwili";
  if (s.resume_pending && s.next_window_at)
    return `wznowienie ${formatDateTime(s.next_window_at)}`;
  if (s.next_start_at) return formatDateTime(s.next_start_at);
  return "brak terminu";
}

export function Schedules() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const editable = can("scan:run");
  const list = useQuery({
    queryKey: ["discovery-schedules"],
    queryFn: api.discoverySchedules,
    refetchInterval: 15_000,
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteDiscoverySchedule(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["discovery-schedules"] }),
  });
  const [editing, setEditing] = useState<{ id: string | null; input: DiscoveryScheduleInput }>({
    id: null,
    input: EMPTY,
  });
  const [formKey, setFormKey] = useState(0);
  const reset = () => {
    setEditing({ id: null, input: EMPTY });
    setFormKey((k) => k + 1);
  };

  return (
    <div className="space-y-4">
      <PageHeader
        title="Harmonogram discovery"
        description="Cykliczne przebiegi w oknach czasowych, z wznowieniem po przekroczeniu okna."
      />
      {editable && (
        <ScheduleForm
          key={formKey}
          initial={editing.input}
          editingId={editing.id}
          onDone={reset}
        />
      )}
      <Card>
        <CardHeader>
          <CardTitle>Harmonogramy</CardTitle>
          <CardDescription>
            Zegar sprawdza harmonogramy co minutę. Każdy cel i tak przechodzi przez zatwierdzony
            zakres i limity tempa.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <QueryState
            isPending={list.isPending}
            error={list.error}
            empty={(list.data?.length ?? 0) === 0}
            emptyText="Brak harmonogramów."
          />
          {remove.error && <p className="text-sm text-red-700">{remove.error.message}</p>}
          {list.data && list.data.length > 0 && (
            <Table>
              <thead>
                <tr>
                  <Th>Nazwa</Th>
                  <Th>Cele</Th>
                  <Th>Częstotliwość i okno</Th>
                  <Th>Następny start</Th>
                  <Th>Ostatni przebieg</Th>
                  {editable && <Th>Zmiana</Th>}
                </tr>
              </thead>
              <tbody>
                {list.data.map((s) => {
                  const status = s.last_run ? RUN_STATUS[s.last_run.status] : undefined;
                  return (
                    <tr key={s.id} data-demo="schedule-row">
                      <Td>
                        {s.name}
                        {s.in_window && (
                          <div>
                            <Badge variant="info">okno trwa</Badge>
                          </div>
                        )}
                      </Td>
                      <Td className="font-mono text-xs">
                        {s.targets.slice(0, 3).join(", ")}
                        {s.targets_count > 3 && ` +${s.targets_count - 3}`}
                      </Td>
                      <Td className="text-sm">
                        {frequencyLabel(s.interval_minutes)}, {s.window_start}–{s.window_end}
                        <div className="text-xs text-muted-foreground">
                          {daysLabel(s.days)} · {s.timezone}
                        </div>
                      </Td>
                      <Td className="text-sm">{nextLabel(s)}</Td>
                      <Td className="text-sm">
                        {s.last_run ? (
                          <>
                            <Link className="text-primary underline" to={`/discovery/${s.last_run.id}`}>
                              {formatDateTime(s.last_run.created_at)}
                            </Link>{" "}
                            <Badge variant={status?.variant ?? "neutral"}>
                              {status?.label ?? s.last_run.status}
                            </Badge>
                          </>
                        ) : (
                          "jeszcze nie było"
                        )}
                      </Td>
                      {editable && (
                        <Td className="whitespace-nowrap">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setEditing({
                                id: s.id,
                                input: {
                                  name: s.name,
                                  text: s.targets.join("\n"),
                                  interval_minutes: s.interval_minutes,
                                  window_start: s.window_start,
                                  window_end: s.window_end,
                                  days: s.days,
                                  timezone: s.timezone,
                                  enabled: s.enabled,
                                  settings: s.settings,
                                },
                              });
                              setFormKey((k) => k + 1);
                            }}
                          >
                            Edytuj
                          </Button>{" "}
                          <Button size="sm" variant="ghost" onClick={() => remove.mutate(s.id)}>
                            Usuń
                          </Button>
                        </Td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
