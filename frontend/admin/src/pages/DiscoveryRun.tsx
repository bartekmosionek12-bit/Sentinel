import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, PencilLine, Send } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

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
import { api, type DiscoveryHost, type HttpFingerprint } from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";

import { CONFIDENCE_VARIANT, formatSeconds, HOST_STATE } from "@/labels";
import { Progress, RunStatus } from "@/pages/Discovery";

export function HostStateBadge({ state }: { state: DiscoveryHost["state"] }) {
  if (!state) return <Badge variant="neutral">Brak historii</Badge>;
  const item = HOST_STATE[state.state] ?? {
    label: state.label,
    variant: "neutral" as const,
    hint: "",
  };
  return (
    <Badge variant={item.variant} title={item.hint}>
      {item.label}
    </Badge>
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
];

function HostEditor({ host }: { host: DiscoveryHost }) {
  const queryClient = useQueryClient();
  const [values, setValues] = useState<Record<string, string>>({});
  const save = useMutation({
    mutationFn: async () => {
      for (const [field, value] of Object.entries(values)) {
        await api.setOverride(host.ip, field, value.trim() || null);
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
              value={values[field] ?? String(host[field as keyof DiscoveryHost] ?? "")}
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
      <div className="flex flex-wrap gap-2">
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

export function DiscoveryRunPage() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const [open, setOpen] = useState<string | null>(null);
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
  const list = [...(hosts.data ?? [])].sort((a, b) => b.flags.length - a.flags.length);
  const sweep = r?.batches.filter((b) => b.phase === "sweep") ?? [];
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
          </div>
        </div>
      )}

      {sweep.length > 0 && (
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="text-lg">Paczki</CardTitle>
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

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Hosty ({list.length})</CardTitle>
          <CardDescription>
            Kliknij adres, żeby zobaczyć kartę hosta. Zaznacz hosty, żeby wysłać je do DefectDojo.
          </CardDescription>
          <div className="flex flex-wrap gap-2 pt-2">
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
          {list.length > 0 && (
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
                {list.map((host) => (
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
      <tr data-demo={`host-${host.ip}`}>
        <Td>
          <input
            type="checkbox"
            className="size-4 accent-[var(--color-primary)]"
            checked={selected}
            onChange={onToggle}
            aria-label={`Zaznacz ${host.ip}`}
          />
        </Td>
        <Td>
          <button
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
