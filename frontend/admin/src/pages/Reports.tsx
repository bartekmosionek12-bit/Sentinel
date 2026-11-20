import { useMutation, useQueryClient } from "@tanstack/react-query";
import { FilePlus2, Sparkles } from "lucide-react";
import { useNavigate } from "react-router-dom";

import { ReportPage, ReportsPage } from "@shared/components/ReportPages";
import { Button } from "@shared/components/ui/button";
import { api } from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";

function CreateReport() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const create = useMutation({
    mutationFn: api.createReport,
    onSuccess: (report) => {
      void queryClient.invalidateQueries({ queryKey: ["reports"] });
      void navigate(`/raporty/${report.id}`);
    },
  });
  if (!can("reports:generate")) return null;
  return (
    <div className="space-y-1 text-right">
      <Button onClick={() => create.mutate()} disabled={create.isPending}>
        <FilePlus2 className="size-4" aria-hidden />
        Nowy raport o stanie
      </Button>
      {create.error && (
        <p className="text-xs text-red-700">{create.error.message}</p>
      )}
    </div>
  );
}

function RequestSummary({ id }: { id: string }) {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const request = useMutation({
    mutationFn: () => api.requestReportSummary(id),
    onSuccess: () => {
      // Model pracuje w tle (kolejka llm); odśwież raport po chwili.
      window.setTimeout(
        () => void queryClient.invalidateQueries({ queryKey: ["report", id] }),
        15_000,
      );
    },
  });
  if (!can("reports:generate")) return null;
  return (
    <div className="space-y-1 text-right">
      <Button
        variant="outline"
        onClick={() => request.mutate()}
        disabled={request.isPending}
      >
        <Sparkles className="size-4" aria-hidden />
        Poproś model o „W skrócie”
      </Button>
      {request.isSuccess && (
        <p className="text-xs text-muted-foreground">
          Zlecono. Model pracuje w tle.
        </p>
      )}
      {request.error && (
        <p className="text-xs text-red-700">{request.error.message}</p>
      )}
    </div>
  );
}

export function Reports() {
  return <ReportsPage basePath="/raporty" actions={<CreateReport />} />;
}

export function ReportDetail() {
  return (
    <ReportPage
      backTo="/raporty"
      actions={(id) => <RequestSummary id={id} />}
    />
  );
}
