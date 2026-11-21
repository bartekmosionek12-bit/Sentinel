import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { PageHeader, QueryState } from "@shared/components/page";
import { Badge } from "@shared/components/ui/badge";
import { Button } from "@shared/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@shared/components/ui/card";
import { Input, Select } from "@shared/components/ui/input";
import { Table, Td, Th } from "@shared/components/ui/table";
import { api, type ScanAction } from "@shared/lib/api";
import { SignedBy } from "@shared/lib/auth";
import { formatDateTime } from "@shared/lib/utils";

const STATUS: Record<
  string,
  { label: string; variant: "ok" | "warn" | "danger" | "neutral" | "info" }
> = {
  planned: { label: "Zaplanowana", variant: "neutral" },
  running: { label: "W toku", variant: "info" },
  done: { label: "Wykonana", variant: "ok" },
  awaiting_approval: { label: "Czeka na zgodę", variant: "warn" },
  denied: { label: "Zablokowana", variant: "danger" },
  failed: { label: "Błąd narzędzia", variant: "danger" },
};

const LEVELS: Record<number, string> = { 1: "L1 lekka", 2: "L2 inwazyjna", 3: "L3 red team" };
const TRIGGERS: Record<string, string> = {
  manual: "ręcznie",
  scheduled: "harmonogram",
  seed_demo: "seed_demo",
  agent: "zadanie agenta",
};

function StatusBadge({ status }: { status: string }) {
  const item = STATUS[status] ?? { label: status, variant: "neutral" as const };
  return <Badge variant={item.variant}>{item.label}</Badge>;
}

function Approvals({ actions }: { actions: ScanAction[] }) {
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const refresh = () => {
    setReason("");
    void queryClient.invalidateQueries();
    window.setTimeout(() => void queryClient.invalidateQueries(), 5000);
  };
  const approve = useMutation({
    mutationFn: (id: string) => api.approveAction(id, reason.trim()),
    onSuccess: refresh,
  });
  const reject = useMutation({
    mutationFn: (id: string) => api.rejectAction(id, reason.trim()),
    onSuccess: refresh,
  });
  const ready = reason.trim().length >= 3;
  const busy = approve.isPending || reject.isPending;
  const failure = approve.error ?? reject.error;

  return (
    <Card className="mb-6 border-amber-300">
      <CardHeader>
        <CardTitle>Czeka na zgodę człowieka ({actions.length})</CardTitle>
        <CardDescription>
          Bardziej inwazyjne skany nie uruchamiają się same. Po zatwierdzeniu akcja i tak przechodzi
          przez kontrolę zakresu.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="mb-4 flex flex-wrap items-end gap-3">
          <SignedBy />
          <label className="min-w-64 flex-1 text-xs font-medium">
            Uzasadnienie decyzji (wymagane)
            <Input
              className="mt-1"
              maxLength={2000}
              placeholder="np. okno serwisowe uzgodnione z właścicielem"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </label>
        </div>
        {failure && (
          <p className="mb-3 text-sm text-red-700" role="alert">
            {failure.message}
          </p>
        )}
        <Table>
          <thead>
            <tr>
              <Th>Cel</Th>
              <Th>Akcja</Th>
              <Th>Reguła i powód</Th>
              <Th>Decyzja</Th>
            </tr>
          </thead>
          <tbody>
            {actions.map((action) => (
              <tr key={action.id}>
                <Td className="font-medium">{action.target}</Td>
                <Td>
                  {action.tool}, porty {action.params.ports}
                  <br />
                  <Badge variant="warn">{LEVELS[action.intrusiveness]}</Badge>
                </Td>
                <Td>
                  <span className="font-mono text-xs">{action.rule_name}</span>
                  <br />
                  <span className="text-muted-foreground">{action.reason}</span>
                </Td>
                <Td>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      disabled={!ready || busy}
                      onClick={() => approve.mutate(action.id)}
                    >
                      Zatwierdź
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={!ready || busy}
                      onClick={() => reject.mutate(action.id)}
                    >
                      Odrzuć
                    </Button>
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </CardContent>
    </Card>
  );
}

export function Scans() {
  const queryClient = useQueryClient();
  const [fromRun, setFromRun] = useState("");
  const [toRun, setToRun] = useState("");
  const [targetText, setTargetText] = useState("");
  const [targetFormat, setTargetFormat] = useState<"manual" | "csv" | "json">("manual");
  const [overrideHost, setOverrideHost] = useState("");
  const [overrideNote, setOverrideNote] = useState("");
  const [dojoSelected, setDojoSelected] = useState<string[]>([]);
  const runs = useQuery({
    queryKey: ["scans"],
    queryFn: api.scans,
    refetchInterval: 10_000,
  });
  const from = fromRun || runs.data?.[1]?.id || "";
  const to = toRun || runs.data?.[0]?.id || "";
  const differences = useQuery({
    queryKey: ["scan-diff", from, to],
    queryFn: () => api.scanDiff(from, to),
    enabled: Boolean(from && to && from !== to),
  });
  const targets = useQuery({queryKey: ["scan-targets"], queryFn: api.scanTargets});
  const previewTargets = useMutation({mutationFn: () => api.previewScanTargets(targetText, targetFormat)});
  const saveTargets = useMutation({mutationFn: () => api.saveScanTargets(targetText, targetFormat), onSuccess: () => void queryClient.invalidateQueries({queryKey: ["scan-targets"]})});
  const importResults = useMutation({mutationFn: ({text, format}: {text: string; format: "json" | "csv" | "xml"}) => api.importScanResults(text, format), onSuccess: () => void queryClient.invalidateQueries({queryKey: ["scans"]})});
  const latestId = runs.data?.[0]?.id || "";
  const latestResults = useQuery({queryKey: ["scan-results", latestId], queryFn: () => api.scanResults(latestId), enabled: Boolean(latestId)});
  const saveOverride = useMutation({mutationFn: () => api.overrideScanResult(overrideHost, "note", overrideNote), onSuccess: () => void queryClient.invalidateQueries({queryKey: ["scan-results"]})});
  const dojoStatus = useQuery({queryKey: ["defectdojo-status"], queryFn: api.defectdojoStatus, refetchInterval: 30_000});
  const dojoExport = useMutation({mutationFn: () => api.exportDefectdojo(latestId, dojoSelected.map((key) => {const [host = "", kind = ""] = key.split("|"); return {host, kind};}))});
  const awaiting = useQuery({
    queryKey: ["scan-actions", "awaiting_approval"],
    queryFn: () => api.scanActions("awaiting_approval"),
    refetchInterval: 10_000,
  });
  const trigger = useMutation({
    mutationFn: () => api.triggerScan(),
    onSuccess: () => {
      window.setTimeout(() => void queryClient.invalidateQueries(), 4000);
    },
  });

  return (
    <>
      <PageHeader
        title="Skany"
        description="Co zostało zeskanowane, która reguła o tym zdecydowała i jaką decyzję podjęła kontrola zakresu. Plan układa deterministyczny silnik reguł (rules/scan_rules.yaml)."
      />
      <Card className="mb-6">
        <CardHeader><CardTitle>Cele skanowania</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm">Wpisz IP, CIDR lub domenę, po jednym celu w wierszu. Cele muszą mieścić się w dozwolonym zakresie.</p>
          <textarea className="w-full rounded border p-2" rows={3} value={targetText} onChange={(event) => {setTargetText(event.target.value); setTargetFormat("manual");}} aria-label="Cele skanowania" />
          <input type="file" accept=".csv,.json" aria-label="Plik celów CSV lub JSON" onChange={(event) => {const file = event.target.files?.[0]; if (file) void file.text().then((text) => {setTargetText(text); setTargetFormat(file.name.endsWith(".json") ? "json" : "csv");});}} />
          <div className="flex gap-2"><Button onClick={() => previewTargets.mutate()} disabled={!targetText}>Podgląd</Button><Button onClick={() => saveTargets.mutate()} disabled={!targetText}>Dodaj cele</Button></div>
          {previewTargets.data && <p className="text-sm">Poprawne: {previewTargets.data.targets.map((item) => item.target).join(", ") || "brak"}. Błędy: {previewTargets.data.errors.join("; ") || "brak"}.</p>}
          {saveTargets.data && <p role="status">Dodano: {saveTargets.data.added}. Błędy: {saveTargets.data.errors.join("; ") || "brak"}.</p>}
          <p className="text-sm">Zapisane cele: {targets.data?.map((item) => item.target).join(", ") || "brak — skan całego zakresu"}</p>
        </CardContent>
      </Card>
      <Card className="mb-6"><CardHeader><CardTitle>Import wyników</CardTitle></CardHeader><CardContent className="space-y-2">
        <input type="file" accept=".json,.csv,.xml" aria-label="Wyniki JSON CSV lub nmap XML" onChange={(event) => {const file = event.target.files?.[0]; if (file) void file.text().then((text) => importResults.mutate({text, format: file.name.endsWith(".xml") ? "xml" : file.name.endsWith(".csv") ? "csv" : "json"}));}} />
        {importResults.data && <p role="status">Zaimportowano {importResults.data.hosts} hostów.</p>}
        {importResults.error && <p role="alert">{importResults.error.message}</p>}
      </CardContent></Card>
      {latestResults.data && <Card className="mb-6"><CardHeader><CardTitle>Edycja wyniku</CardTitle></CardHeader><CardContent className="space-y-2">
        <div className="flex flex-wrap gap-2"><Select aria-label="Host wyniku" value={overrideHost} onChange={(event) => setOverrideHost(event.target.value)}><option value="">Wybierz host</option>{Object.keys(latestResults.data.hosts).map((host) => <option key={host}>{host}</option>)}</Select><Input aria-label="Notatka ręczna" value={overrideNote} onChange={(event) => setOverrideNote(event.target.value)} placeholder="Notatka do wyniku" /><Button disabled={!overrideHost} onClick={() => saveOverride.mutate()}>Zapisz nadpisanie</Button></div>
        {Object.entries(latestResults.data.hosts).filter(([, host]) => host.manually_changed).map(([ip, host]) => <p key={ip}>{ip}: {host.note} (zmienione ręcznie)</p>)}
      </CardContent></Card>}
      {latestResults.data && <Card className="mb-6"><CardHeader><CardTitle>DefectDojo lokalnie</CardTitle></CardHeader><CardContent className="space-y-2">
        <p>{dojoStatus.data?.connected ? "Połączony" : `Niedostępny: ${dojoStatus.data?.detail ?? "sprawdzanie"}`}</p>
        {Object.entries(latestResults.data.hosts).flatMap(([host, info]) => (info.flags ?? []).map((flag) => {const key = `${host}|${flag.kind}`; return <label className="block" key={key}><input type="checkbox" checked={dojoSelected.includes(key)} onChange={(event) => setDojoSelected(event.target.checked ? [...dojoSelected, key] : dojoSelected.filter((item) => item !== key))} /> {host}: {flag.kind} (dowody: {flag.confidence})</label>;}))}
        <div className="flex gap-2"><Button disabled={!dojoStatus.data?.connected || dojoSelected.length === 0} onClick={() => dojoExport.mutate()}>Eksportuj wybrane</Button><Button onClick={() => void api.downloadNmapXml(latestId)}>Pobierz nmap XML</Button></div>
        {dojoExport.data && <p role="status">Dodano: {dojoExport.data.created}, pominięto duplikaty: {dojoExport.data.duplicates}.</p>}
        {dojoExport.error && <p role="alert">{dojoExport.error.message}</p>}
      </CardContent></Card>}
      {(runs.data?.length ?? 0) >= 2 && (
        <Card className="mb-6">
          <CardHeader><CardTitle>Porównaj dwa przebiegi</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <Select aria-label="Starszy przebieg" value={from} onChange={(event) => setFromRun(event.target.value)}>{runs.data?.map((run) => <option key={run.id} value={run.id}>{formatDateTime(run.started_at)}</option>)}</Select>
              <Select aria-label="Nowszy przebieg" value={to} onChange={(event) => setToRun(event.target.value)}>{runs.data?.map((run) => <option key={run.id} value={run.id}>{formatDateTime(run.started_at)}</option>)}</Select>
              <Button onClick={() => void api.downloadScanDiff(from, to, "json")}>JSON</Button>
              <Button onClick={() => void api.downloadScanDiff(from, to, "csv")}>CSV</Button>
            </div>
            {differences.data && <Table><thead><tr><Th>Zmiana</Th><Th>Host</Th><Th>Element</Th><Th>Przed</Th><Th>Po</Th></tr></thead><tbody>{differences.data.map((change, index) => <tr key={index}><Td>{change.kind}</Td><Td>{change.host}</Td><Td>{change.item}</Td><Td>{change.before}</Td><Td>{change.after}</Td></tr>)}</tbody></Table>}
          </CardContent>
        </Card>
      )}
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <Button disabled={trigger.isPending} onClick={() => trigger.mutate()}>
          Uruchom skan zakresu
        </Button>
        {trigger.data && (
          <p className="text-sm text-muted-foreground" role="status">
            {trigger.data.detail}. Wynik pojawi się poniżej.
          </p>
        )}
        {trigger.error && (
          <p className="text-sm text-red-700" role="alert">
            {trigger.error.message}
          </p>
        )}
      </div>

      {awaiting.data && awaiting.data.length > 0 && <Approvals actions={awaiting.data} />}

      <QueryState
        isPending={runs.isPending}
        error={runs.error}
        empty={runs.data?.length === 0}
        emptyText="Nie było jeszcze żadnego skanu."
      />
      <div className="space-y-6">
        {runs.data?.map((run) => (
          <Card key={run.id}>
            <CardHeader>
              <div className="flex flex-wrap items-center gap-2">
                <CardTitle>Skan z {formatDateTime(run.started_at)}</CardTitle>
                <Badge variant={run.status === "done" ? "ok" : "info"}>
                  {run.status === "done" ? "zakończony" : "w toku"}
                </Badge>
                <Badge variant="neutral">uruchomiony: {TRIGGERS[run.trigger] ?? run.trigger}</Badge>
              </div>
              <CardDescription>
                {typeof run.summary.addresses_done === "number" && (
                  <span>Postęp: {run.summary.addresses_done}/{String(run.summary.total_addresses ?? "?")} adresów; czas: {String(run.summary.duration_seconds ?? "w toku")} s; ETA: {String(run.summary.eta_seconds ?? "?")} s. </span>
                )}
                {typeof run.summary.note === "string" && run.summary.note
                  ? run.summary.note
                  : `Odpowiada hostów: ${String(run.summary.hosts_up ?? 0)}, nowych: ${String(
                      run.summary.hosts_new ?? 0,
                    )}, nie odpowiada: ${String(run.summary.hosts_missing ?? 0)}. Nowe zagrożenia: ${String(
                      run.summary.findings_created ?? 0,
                    )}, powiadomienia: ${String(run.summary.notifications ?? 0)}.`}
              </CardDescription>
              <div className="flex gap-2"><Button onClick={() => void api.downloadScanResults(run.id, "json")}>Eksport JSON</Button><Button onClick={() => void api.downloadScanResults(run.id, "csv")}>Eksport CSV</Button></div>
            </CardHeader>
            {run.actions.length > 0 && (
              <Table>
                <thead>
                  <tr>
                    <Th>Cel</Th>
                    <Th>Reguła</Th>
                    <Th>Poziom</Th>
                    <Th>Stan</Th>
                    <Th>Zgoda</Th>
                    <Th>Wynik</Th>
                  </tr>
                </thead>
                <tbody>
                  {run.actions.map((action) => (
                    <tr key={action.id}>
                      <Td className="font-medium whitespace-nowrap">{action.target}</Td>
                      <Td>
                        <span className="font-mono text-xs">{action.rule_name}</span>
                        <br />
                        <span className="text-xs text-muted-foreground">{action.reason}</span>
                      </Td>
                      <Td className="whitespace-nowrap">{LEVELS[action.intrusiveness]}</Td>
                      <Td>
                        <StatusBadge status={action.status} />
                      </Td>
                      <Td>
                        {action.approval_source ??
                          (action.intrusiveness >= 2 ? "brak" : "niewymagana")}
                      </Td>
                      <Td className="text-muted-foreground">{action.detail}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
        ))}
      </div>
    </>
  );
}
