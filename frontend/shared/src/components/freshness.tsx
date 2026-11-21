/** Świeżość danych i prośba o nowe skanowanie (moduł 21, ARCHITECTURE §25.1). */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Clock, RefreshCw, TriangleAlert } from "lucide-react";
import { useState } from "react";

import { Badge } from "@shared/components/ui/badge";
import { Button } from "@shared/components/ui/button";
import { Input } from "@shared/components/ui/input";
import { api, type ScanRequest, type ScanRequestScope } from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";
import { formatDateTime } from "@shared/lib/utils";

const REQUEST_STATUS: Record<
  ScanRequest["status"],
  { label: string; variant: "ok" | "warn" | "danger" | "neutral" | "info" }
> = {
  pending: { label: "czeka na zatwierdzenie", variant: "warn" },
  approved: { label: "zatwierdzona, skan w toku", variant: "info" },
  rejected: { label: "odrzucona", variant: "neutral" },
  done: { label: "wyniki gotowe", variant: "ok" },
  failed: { label: "skan nie powiódł się", variant: "danger" },
};

export function RequestStatus({ request }: { request: ScanRequest }) {
  const item = REQUEST_STATUS[request.status];
  return <Badge variant={item.variant}>{item.label}</Badge>;
}

/** Prośba do admina. Menedżer niczego nie skanuje: skan uruchamia dopiero zatwierdzenie. */
export function ScanRequestButton({
  scope = "organization",
  scopeRef = null,
  label = "Poproś o nowe skanowanie",
}: {
  scope?: ScanRequestScope;
  scopeRef?: string | null;
  label?: string;
}) {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const send = useMutation({
    mutationFn: () => api.requestScan(scope, scopeRef, reason.trim()),
    onSuccess: () => {
      setOpen(false);
      setReason("");
      void queryClient.invalidateQueries({ queryKey: ["scan-requests"] });
    },
  });
  if (!can("scan:request")) return null;
  if (!open)
    return (
      <span className="inline-flex flex-wrap items-center gap-2">
        <Button variant="outline" size="sm" onClick={() => setOpen(true)} data-demo="scan-request">
          <RefreshCw className="size-4" aria-hidden /> {label}
        </Button>
        {send.data && (
          <span role="status" className="text-xs text-muted-foreground">
            Prośba wysłana do zespołu bezpieczeństwa ({send.data.scope_label}).
          </span>
        )}
      </span>
    );
  return (
    <form
      className="flex flex-wrap items-center gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        send.mutate();
      }}
    >
      <Input
        autoFocus
        value={reason}
        onChange={(event) => setReason(event.target.value)}
        placeholder="Dlaczego? (opcjonalnie)"
        aria-label="Powód prośby o skanowanie"
        className="h-8 max-w-xs"
      />
      <Button size="sm" type="submit" disabled={send.isPending}>
        Wyślij prośbę
      </Button>
      <Button size="sm" variant="ghost" type="button" onClick={() => setOpen(false)}>
        Anuluj
      </Button>
      <span className="w-full text-xs text-muted-foreground">
        Skan uruchomi zespół bezpieczeństwa po zatwierdzeniu. Dostaniesz powiadomienie, gdy wyniki
        będą gotowe.
      </span>
      {send.error && (
        <span role="alert" className="text-xs text-red-700">
          {send.error.message}
        </span>
      )}
    </form>
  );
}

/** „Dane ze skanu sprzed 2 godz.”, ostrzeżenie po progu i prośba o nowe skanowanie. */
export function FreshnessNote({
  scope = "organization",
  scopeRef = null,
}: {
  scope?: ScanRequestScope;
  scopeRef?: string | null;
}) {
  const fresh = useQuery({ queryKey: ["freshness"], queryFn: api.freshness, refetchInterval: 5_000 });
  const mine = useQuery({
    queryKey: ["scan-requests"],
    queryFn: () => api.scanRequests(),
    refetchInterval: 5_000,
    enabled: useAuth().can("scan:request"),
  });
  if (!fresh.data) return null;
  const { stale, label, threshold_hours, last_scan_at } = fresh.data;
  const latest = mine.data?.[0];
  return (
    <div
      data-demo="freshness"
      className={
        stale
          ? "flex flex-wrap items-center gap-3 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900"
          : "flex flex-wrap items-center gap-3 text-sm text-muted-foreground"
      }
    >
      {stale ? (
        <TriangleAlert className="size-4 shrink-0" aria-hidden />
      ) : (
        <Clock className="size-4 shrink-0" aria-hidden />
      )}
      <span title={last_scan_at ? formatDateTime(last_scan_at) : undefined}>
        {label}
        {stale && ` Starsze niż ${threshold_hours} godz.: obraz może być nieaktualny.`}
      </span>
      <ScanRequestButton scope={scope} scopeRef={scopeRef} />
      {latest && (
        <span className="flex items-center gap-2 text-xs">
          Twoja ostatnia prośba ({latest.scope_label}): <RequestStatus request={latest} />
        </span>
      )}
    </div>
  );
}
