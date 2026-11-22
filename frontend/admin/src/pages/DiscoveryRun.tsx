import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileText, PencilLine, Send } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

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
import { api, type DiscoveryHost, type DiscoveryRun, type HttpFingerprint } from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";
import { formatDateTime } from "@shared/lib/utils";

import { CONFIDENCE_VARIANT, formatSeconds, HOST_STATE } from "@/labels";
import { Progress, RunStatus } from "@/pages/Discovery";

export function HostStateBadge({ state }: { state: DiscoveryHost["state"] }) {
  if (!state) return <Badge variant="neutral">Brak historii</Badge>;
  const item = HOST_STATE[state.state] ?? {
    label: state.label,
    variant: "neutral" as const,
    hint: "",
  };
  const when = state.time_profile?.label;
  return (
    <span className="inline-flex flex-wrap gap-1">
      <Badge variant={item.variant} title={item.hint}>
        {item.label}
      </Badge>
      {when && (
        <Badge variant="info" title="Wzorzec z przebiegów w dzień (7–19) i w nocy">
          {when}
        </Badge>
      )}
    </span>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium tracking-wide text-muted-foreground uppercase">{label}</dt>
      <dd className="mt-0.5 text-sm break-words">{children}</dd>
    </div>
  );
}

function HttpCard({ item }: { item: HttpFingerprint }) {
  const statusVariant =
    item.status === null
      ? "danger"
      : item.status < 300
        ? "ok"
        : item.status < 400
          ? "info"
          : "warn";
  return (
    <div className="rounded-md border border-border p-4" data-demo="http-card">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm">{item.url}</span>
        <Badge variant={statusVariant}>HTTP {item.status ?? "brak odpowiedzi"}</Badge>
        {item.technologies.map((t) => (
          <Badge key={t} variant="neutral" icon={false}>
            {t}
          </Badge>
        ))}
      </div>
      <dl className="grid gap-3 md:grid-cols-2">
        <Fact label="Tytuł strony">{item.title || "–"}</Fact>
        <Fact label="Przekierowania">
          {item.redirects.length ? item.redirects.join(" → ") : "brak"}
        </Fact>
        <Fact label="Certyfikat TLS">
          {item.tls
            ? `${item.tls.subject ?? "?"} · wystawca ${item.tls.issuer ?? "?"} · ważny do ${item.tls.not_after ?? "?"}`
            : item.scheme === "https"
              ? "nie udało się odczytać"
              : "brak (HTTP)"}
        </Fact>
        <Fact label="Hash favicony (mmh3)">{item.favicon_hash ?? "brak favicony"}</Fact>
        <Fact label="Ciasteczka">
          {item.cookies.length
            ? item.cookies.map((c) => (
                <span key={c.name} className="mr-2 inline-block">
                  <span className="font-mono">{c.name}</span>{" "}
                  <span className="text-muted-foreground">
                    ({c.secure ? "Secure" : "bez Secure"},{" "}
                    {c.httponly ? "HttpOnly" : "bez HttpOnly"})
                  </span>
                </span>
              ))
            : "brak"}
        </Fact>
        <Fact label="Sprawdzone ścieżki (GET)">
          {Object.entries(item.paths).length
            ? Object.entries(item.paths)
                .map(([path, code]) => `${path}: ${code}`)
                .join(", ")
            : "–"}
        </Fact>
      </dl>
      <details className="mt-3">
        <summary className="cursor-pointer text-sm text-primary">
          Nagłówki odpowiedzi ({Object.keys(item.headers).length})
        </summary>
        <table className="mt-2 w-full text-sm">
          <tbody>
            {Object.entries(item.headers).map(([k, v]) => (
              <tr key={k}>
                <td className="py-0.5 pr-3 align-top font-mono text-muted-foreground">{k}</td>
                <td className="py-0.5 font-mono break-all">{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  );
}

const EDITABLE: { field: string; label: string; placeholder: string }[] = [
  {
    field: "hostname",
    label: "Nazwa hosta",
    placeholder: "np. portal.agh.example",
  },
  {
    field: "criticality",
    label: "Krytyczność",
    placeholder: "niska / średnia / wysoka",
  },
  {
    field: "status",
    label: "Status obsługi",
    placeholder: "np. sprawdzone, do wyjaśnienia",
  },
  {
    field: "note",
    label: "Notatka",
    placeholder: "np. środowisko testowe zespołu X",
  },
  {
    field: "tags",
    label: "Tagi (po przecinku)",
    placeholder: "np. dmz, zespół-x, do-weryfikacji",
  },
];

function fieldValue(host: DiscoveryHost, field: string): string {
  if (field === "tags") return host.tags.join(", ");
  return String(host[field as keyof DiscoveryHost] ?? "");
}

function toValue(field: string, value: string): unknown {
  if (field === "tags") {
    const tags = [
      ...new Set(
        value
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      ),
    ];
    return tags.length ? tags : null;
  }
  return value.trim() || null;
}

function HostEditor({ host }: { host: DiscoveryHost }) {
  const queryClient = useQueryClient();
  const [values, setValues] = useState<Record<string, string>>({});
  const save = useMutation({
    mutationFn: async () => {
      for (const [field, value] of Object.entries(values)) {
        await api.setOverride(host.ip, field, toValue(field, value));
      }
    },
    onSuccess: () => {
      setValues({});
      void queryClient.invalidateQueries({ queryKey: ["discovery-hosts"] });
    },
  });
  return (
    <div className="rounded-md border border-border p-4" data-demo="host-editor">
      <p className="mb-3 flex items-center gap-2 text-sm font-semibold">
        <PencilLine className="size-4 text-primary" aria-hidden />
        Ręczna edycja (kolejny skan jej nie nadpisze)
      </p>
      <div className="grid gap-3 md:grid-cols-2">
        {EDITABLE.map(({ field, label, placeholder }) => (
          <label key={field} className="text-sm font-medium">
            {label}
            {host.edited.includes(field) && (
              <Badge className="ml-2" variant="info">
                Zmienione ręcznie
              </Badge>
            )}
            <Input
              data-demo={`edit-${field}`}
              className="mt-1"
              placeholder={placeholder}
              value={values[field] ?? fieldValue(host, field)}
              onChange={(e) => setValues((v) => ({ ...v, [field]: e.target.value }))}
            />
          </label>
        ))}
      </div>
      <Button
        data-demo="save-edit"
        className="mt-3"
        disabled={!Object.keys(values).length || save.isPending}
        onClick={() => save.mutate()}
      >
        Zapisz zmiany
      </Button>
      {save.error && <p className="mt-2 text-sm text-red-700">{save.error.message}</p>}
    </div>
  );
}

function HostCard({ host }: { host: DiscoveryHost }) {
  const { can } = useAuth();
  return (
    <div className="space-y-4 bg-background p-4" data-demo="host-card">
      <div className="flex flex-wrap gap-2" data-demo="host-flags">
        {host.flags.length === 0 && (
          <span className="text-sm text-muted-foreground">Brak flag.</span>
        )}
        {host.flags.map((flag) => (
          <div key={flag.kind} className="rounded-md border border-border p-3 text-sm">
            <div className="flex items-center gap-2">
              <Badge variant={CONFIDENCE_VARIANT[flag.confidence] ?? "neutral"}>{flag.label}</Badge>
              <span className="text-xs text-muted-foreground">pewność: {flag.confidence}</span>
            </div>
            <ul className="mt-1 list-disc pl-5 text-xs text-muted-foreground">
              {flag.evidence.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <Table>
        <thead>
          <tr>
            <Th>Port</Th>
            <Th>Usługa</Th>
            <Th>Produkt i wersja</Th>
          </tr>
        </thead>
        <tbody>
          {host.services.map((s) => (
            <tr key={`${s.port}/${s.protocol}`}>
              <Td className="font-mono">
                {s.port}/{s.protocol ?? "tcp"}
              </Td>
              <Td>{s.name || "?"}</Td>
              <Td>{[s.product, s.version].filter(Boolean).join(" ") || "–"}</Td>
            </tr>
          ))}
        </tbody>
      </Table>
      {host.http.map((item) => (
        <HttpCard key={item.url} item={item} />
      ))}
      {can("findings:update") && <HostEditor host={host} />}
    </div>
  );
}

/** Wstrzymany przebieg: ile zostało, kiedy wznowi harmonogram, ręczne „Wznów”. */
function ResumePanel({
  run,
  canResume,
  onResumed,
}: {
  run: DiscoveryRun;
  canResume: boolean;
  onResumed: (id: string) => void;
}) {
  const [endAt, setEndAt] = useState("");
  const resume = useMutation({
    mutationFn: () => api.resumeDiscovery(run.id, endAt ? new Date(endAt).toISOString() : null),
    onSuccess: (next) => onResumed(next.id),
  });
  const left = run.remaining;
  return (
    <div
      className="mt-2 space-y-2 rounded-md border border-border p-3 text-sm"
      data-demo="run-paused"
    >
      <p>
        Przebieg doszedł do zadanego końca
        {run.deadline ? ` (${formatDateTime(run.deadline)})` : ""}. Rozpoczęte paczki zostały
        dokończone, a stan zapisany: zostało{" "}
        {Number(run.summary?.remaining_addresses ?? 0).toLocaleString("pl-PL")} adresów
        {left ? ` (${left.networks} zakresów, ${left.hosts} hostów bez skanu usług)` : ""}.
        {run.schedule_id && " Harmonogram cykliczny wznowi go sam w kolejnym oknie. "}
        {run.schedule_id && (
          <Link className="text-primary underline" to="/discovery/harmonogram">
            Harmonogram
          </Link>
        )}
      </p>
      {run.resumed_by ? (
        <p>
          Już wznowiony:{" "}
          <Link className="text-primary underline" to={`/discovery/${run.resumed_by}`}>
            przebieg wznowienia
          </Link>
        </p>
      ) : (
        canResume && (
          <div className="flex flex-wrap items-end gap-2">
            <label className="text-xs">
              Nowy koniec (opcjonalnie)
              <Input
                type="datetime-local"
                aria-label="Koniec wznowienia"
                className="mt-1 h-8"
                value={endAt}
                onChange={(e) => setEndAt(e.target.value)}
              />
            </label>
            <Button size="sm" onClick={() => resume.mutate()} disabled={resume.isPending}>
              Wznów
            </Button>
          </div>
        )
      )}
      {resume.error && <p className="text-red-700">{resume.error.message}</p>}
    </div>
  );
}

export function DiscoveryRunPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const { can } = useAuth();
  const [params] = useSearchParams();
  const [open, setOpen] = useState<string | null>(params.get("host"));
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const run = useQuery({
    queryKey: ["discovery-run", id],
    queryFn: () => api.discoveryRun(id),
    refetchInterval: (q) =>
      q.state.data && ["running", "queued", "stopping"].includes(q.state.data.status)
        ? 2000
        : false,
  });
  const hosts = useQuery({
    queryKey: ["discovery-hosts", id],
    queryFn: () => api.discoveryHosts(id),
    refetchInterval: run.data?.status === "running" ? 3000 : false,
  });
  const dojo = useQuery({ queryKey: ["dojo-status"], queryFn: api.dojoStatus });
  const queryClient = useQueryClient();
  const exportDojo = useMutation({
    mutationFn: () => api.dojoExport(id, [...selected]),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["dojo-status"] }),
  });

  const r = run.data;
  const list = [...(hosts.data ?? [])].sort(
    (a, b) => b.flags.length - a.flags.length || a.ip.localeCompare(b.ip, "en", { numeric: true }),
  );
  const sweep = r?.batches.filter((b) => b.phase === "sweep") ?? [];
  const [tag, setTag] = useState("");
  const allTags = [...new Set(list.flatMap((h) => h.tags))].sort();
  const shown = tag ? list.filter((h) => h.tags.includes(tag)) : list;
  const toggle = (ip: string) =>
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });

  return (
    <>
      <PageHeader
        title={r ? r.name || "Przebieg discovery" : "Przebieg discovery"}
        description="Paczki z czasem trwania, wykryte hosty z usługami, fingerprintem HTTP i flagami. Ręczne zmiany są trzymane osobno i przeżywają kolejne skany."
      />
      <QueryState isPending={run.isPending} error={run.error} empty={false} emptyText="" />
      {r && (
        <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-5" data-demo="run-stats">
          {[
            ["Status", <RunStatus key="s" run={r} />],
            ["Adresy", r.addresses_total.toLocaleString("pl-PL")],
            ["Aktywne hosty", String(r.hosts_up)],
            ["Czas", formatSeconds(r.duration_seconds)],
            ["ETA", r.status === "running" ? formatSeconds(r.eta_seconds) : "–"],
          ].map(([label, value]) => (
            <Card key={String(label)}>
              <CardHeader>
                <CardDescription>{label}</CardDescription>
                <div className="text-3xl font-bold tabular-nums">{value}</div>
              </CardHeader>
            </Card>
          ))}
          <div className="sm:col-span-2 xl:col-span-5">
            <Progress value={r.progress} />
            <p className="mt-1 text-sm text-muted-foreground tabular-nums">
              {r.addresses_done.toLocaleString("pl-PL")} z{" "}
              {r.addresses_total.toLocaleString("pl-PL")} adresów · {r.batches_done} paczek ·
              workery {r.settings.workers ?? "–"} · tempo {r.settings.max_rate ?? "–"} pakietów/s na
              worker · nmap -T
              {r.settings.timing ?? 3}
            </p>
            {r.error && <p className="text-sm text-red-700">{r.error}</p>}
            {r.status === "paused" && (
              <ResumePanel
                run={r}
                canResume={can("scan:run")}
                onResumed={(next) => navigate(`/discovery/${next}`)}
              />
            )}
            {Number(r.summary?.retried ?? 0) > 0 && (
              <p className="text-xs text-muted-foreground">
                Ponowna próba dla {String(r.summary?.retried)} hostów, które odpowiadały poprzednio;
                odpowiedziało {String(r.summary?.recovered_on_retry ?? 0)}.
              </p>
            )}
          </div>
        </div>
      )}

      {r && (
        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Paczki</CardTitle>
            <CardDescription>
              Rozmiar kolejnej paczki dobierany do zmierzonej szybkości. Ostatnie na górze.
            </CardDescription>
          </CardHeader>
          <CardContent className="max-h-80 overflow-y-auto" data-demo="batches">
            <Table>
              <thead>
                <tr>
                  <Th>Zakres</Th>
                  <Th>Adresów</Th>
                  <Th>Hosty</Th>
                  <Th>Czas</Th>
                  <Th>Status</Th>
                </tr>
              </thead>
              <tbody>
                {sweep.length === 0 && (
                  <tr>
                    <Td colSpan={5} className="text-muted-foreground">
                      {r?.source === "import"
                        ? "Przebieg z importu: bez paczek skanowania."
                        : "Pierwsza paczka w toku…"}
                    </Td>
                  </tr>
                )}
                {sweep.slice(0, 40).map((b) => (
                  <tr key={b.target}>
                    <Td className="font-mono">{b.target}</Td>
                    <Td className="tabular-nums">{b.addresses}</Td>
                    <Td className="tabular-nums">{b.hosts_up}</Td>
                    <Td className="tabular-nums">{(b.duration_ms / 1000).toFixed(1)} s</Td>
                    <Td>
                      <Badge variant={b.status === "done" ? "ok" : "danger"}>
                        {b.status === "done" ? "Gotowa" : b.detail || "Błąd"}
                      </Badge>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </CardContent>
        </Card>
      )}

      {list.length > 0 && <ServiceGroups hosts={list} />}
      <Card data-demo="hosts">
        <CardHeader>
          <CardTitle>Hosty ({list.length})</CardTitle>
          <CardDescription>
            Kliknij adres, żeby zobaczyć kartę hosta. Zaznacz hosty, żeby wysłać je do DefectDojo.
          </CardDescription>
          <div className="flex flex-wrap gap-2 pt-2" data-demo="export-buttons">
            {(["json", "csv", "nmap"] as const).map((f) => (
              <Button
                key={f}
                size="sm"
                variant="outline"
                onClick={() => void api.exportDiscovery(id, f)}
              >
                <Download className="size-3.5" aria-hidden />
                {f === "nmap" ? "nmap XML" : f.toUpperCase()}
              </Button>
            ))}
            {(["html", "json", "csv"] as const).map((f) => (
              <Button
                key={`report-${f}`}
                size="sm"
                variant="outline"
                onClick={() => void api.discoveryReport(id, f)}
              >
                <FileText className="size-3.5" aria-hidden />
                Raport {f.toUpperCase()}
              </Button>
            ))}
            {can("defectdojo:export") && (
              <Button
                data-demo="dojo-export"
                size="sm"
                disabled={!selected.size || exportDojo.isPending}
                onClick={() => exportDojo.mutate()}
              >
                <Send className="size-3.5" aria-hidden />
                Wyślij do DefectDojo ({selected.size})
              </Button>
            )}
            {dojo.data && (
              <Badge variant={dojo.data.ok ? "ok" : "warn"}>
                DefectDojo: {dojo.data.ok ? "połączono" : dojo.data.detail}
              </Badge>
            )}
          </div>
          {exportDojo.data && (
            <p className="text-sm" data-demo="dojo-result">
              <Badge variant="ok">
                Wysłano {exportDojo.data.sent} findingów (Info)
                {exportDojo.data.skipped_duplicates
                  ? `, pominięto ${exportDojo.data.skipped_duplicates} duplikatów`
                  : ""}
              </Badge>
              {exportDojo.data.detail ? ` ${exportDojo.data.detail}` : ""}
              {dojo.data?.url && exportDojo.data.test && (
                <a
                  className="ml-2 text-primary underline"
                  href={`${dojo.data.url.replace("dd-nginx:8080", "localhost:8081")}/test/${exportDojo.data.test}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  Otwórz test w DefectDojo
                </a>
              )}
            </p>
          )}
          {exportDojo.error && <p className="text-sm text-red-700">{exportDojo.error.message}</p>}
        </CardHeader>
        <CardContent>
          <QueryState
            isPending={hosts.isPending}
            error={hosts.error}
            empty={list.length === 0}
            emptyText="Jeszcze nie wykryto żadnego hosta."
          />
          {allTags.length > 0 && (
            <div className="mb-3 flex flex-wrap items-center gap-2 text-sm" data-demo="tag-filter">
              Tagi:
              <Button size="sm" variant={tag ? "ghost" : "outline"} onClick={() => setTag("")}>
                wszystkie
              </Button>
              {allTags.map((t) => (
                <Button
                  key={t}
                  size="sm"
                  variant={tag === t ? "outline" : "ghost"}
                  onClick={() => setTag(t)}
                >
                  #{t}
                </Button>
              ))}
            </div>
          )}
          {shown.length > 0 && (
            <Table>
              <thead>
                <tr>
                  <Th className="w-8">
                    <span className="sr-only">Zaznacz</span>
                  </Th>
                  <Th>Adres</Th>
                  <Th>Stan</Th>
                  <Th>Usługi</Th>
                  <Th>Technologie</Th>
                  <Th>Flagi</Th>
                </tr>
              </thead>
              <tbody>
                {shown.map((host) => (
                  <HostRows
                    key={host.ip}
                    host={host}
                    open={open === host.ip}
                    selected={selected.has(host.ip)}
                    onToggle={() => toggle(host.ip)}
                    onOpen={() => setOpen(open === host.ip ? null : host.ip)}
                  />
                ))}
              </tbody>
            </Table>
          )}
        </CardContent>
      </Card>
      <p className="mt-4 text-sm">
        <Link className="text-primary underline" to="/discovery">
          Wróć do listy przebiegów
        </Link>
      </p>
    </>
  );
}

function HostRows({
  host,
  open,
  selected,
  onToggle,
  onOpen,
}: {
  host: DiscoveryHost;
  open: boolean;
  selected: boolean;
  onToggle: () => void;
  onOpen: () => void;
}) {
  return (
    <>
      <tr data-demo="host-row" data-ip={host.ip}>
        <Td>
          <input
            type="checkbox"
            data-demo="host-select"
            className="size-4 accent-[var(--color-primary)]"
            checked={selected}
            onChange={onToggle}
            aria-label={`Zaznacz ${host.ip}`}
          />
        </Td>
        <Td>
          <button
            data-demo="host-open"
            className="text-left font-mono font-semibold text-primary underline"
            onClick={onOpen}
          >
            {host.ip}
          </button>
          <p className="text-xs text-muted-foreground">
            {host.hostname ?? "bez nazwy"}
            {host.edited.length > 0 && (
              <Badge className="ml-2" variant="info">
                Zmienione ręcznie
              </Badge>
            )}
          </p>
          {host.note && <p className="text-xs">{host.note}</p>}
          {host.tags.length > 0 && (
            <p className="text-xs text-primary">{host.tags.map((t) => `#${t}`).join(" ")}</p>
          )}
        </Td>
        <Td>
          <HostStateBadge state={host.state} />
        </Td>
        <Td className="font-mono text-xs">
          {host.services.map((s) => `${s.port}/${s.name || "?"}`).join(", ") || "–"}
        </Td>
        <Td className="text-xs">{host.technologies.join(", ") || "–"}</Td>
        <Td>
          <div className="flex flex-wrap gap-1">
            {host.flags.map((f) => (
              <Badge key={f.kind} variant={CONFIDENCE_VARIANT[f.confidence] ?? "neutral"}>
                {f.label}
              </Badge>
            ))}
          </div>
        </Td>
      </tr>
      {open && (
        <tr>
          <td colSpan={6} className="border-b border-border">
            <HostCard host={host} />
          </td>
        </tr>
      )}
    </>
  );
}

/** Grupowanie podobnych usług (brief): ten sam port, usługa i produkt na wielu hostach. */
function ServiceGroups({ hosts }: { hosts: DiscoveryHost[] }) {
  const groups = new Map<string, { label: string; hosts: string[] }>();
  for (const host of hosts) {
    for (const s of host.services) {
      const product = [s.product, s.version].filter(Boolean).join(" ");
      const key = `${s.port}/${s.protocol ?? "tcp"}|${s.name ?? ""}|${product}`;
      const label = `${s.port}/${s.protocol ?? "tcp"} ${s.name || "?"}${product ? ` · ${product}` : ""}`;
      const group = groups.get(key) ?? { label, hosts: [] };
      group.hosts.push(host.hostname ? `${host.hostname} (${host.ip})` : host.ip);
      groups.set(key, group);
    }
    for (const tech of host.technologies) {
      const key = `tech|${tech}`;
      const group = groups.get(key) ?? {
        label: `technologia: ${tech}`,
        hosts: [],
      };
      group.hosts.push(host.hostname ? `${host.hostname} (${host.ip})` : host.ip);
      groups.set(key, group);
    }
  }
  const rows = [...groups.values()].sort(
    (a, b) => b.hosts.length - a.hosts.length || a.label.localeCompare(b.label, "pl"),
  );
  if (!rows.length) return null;
  return (
    <Card className="mb-6" data-demo="service-groups">
      <CardHeader>
        <CardTitle>Grupy podobnych usług</CardTitle>
        <CardDescription>
          Ten sam port, usługa i wersja albo ta sama technologia na wielu hostach: łatwiej ocenić
          skalę i zrobić jedną poprawkę dla całej grupy.
        </CardDescription>
      </CardHeader>
      <CardContent className="max-h-80 overflow-y-auto">
        <Table>
          <thead>
            <tr>
              <Th>Usługa</Th>
              <Th>Hosty</Th>
              <Th>Gdzie</Th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 50).map((g) => (
              <tr key={g.label}>
                <Td className="font-mono text-xs">{g.label}</Td>
                <Td>{g.hosts.length}</Td>
                <Td className="text-xs">
                  {g.hosts.slice(0, 4).join(", ")}
                  {g.hosts.length > 4 && ` +${g.hosts.length - 4}`}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </CardContent>
    </Card>
  );
}
