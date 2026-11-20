import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, FileText, RefreshCw, Sparkles } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { Badge } from "@shared/components/ui/badge";
import { Button } from "@shared/components/ui/button";
import { api, type Audience, type Explanation } from "@shared/lib/api";
import { cn, formatDateTime } from "@shared/lib/utils";

const AUDIENCES: { value: Audience; label: string; hint: string }[] = [
  { value: "executive", label: "Zarządczy", hint: "1–2 zdania dla zarządu" },
  { value: "operational", label: "Operacyjny", hint: "dla kierownika IT" },
  { value: "technical", label: "Techniczny", hint: "dla administratora" },
];

type Live =
  | { state: "idle" }
  | { state: "running"; text: string; note: string }
  | { state: "error"; message: string };

/** Tekst modelu jako zwykły tekst; jedynie fragmenty w `znakach kodu` dostają styl kodu. */
function RichText({ text }: { text: string }) {
  return (
    <>
      {text.split(/(`[^`\n]+`)/g).map((part, index) =>
        part.length > 2 && part.startsWith("`") && part.endsWith("`") ? (
          <code key={index} className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
            {part.slice(1, -1)}
          </code>
        ) : (
          part
        ),
      )}
    </>
  );
}

function ExplanationText({ explanation }: { explanation: Explanation }) {
  return (
    <div className="space-y-2">
      <p className="text-sm font-medium">{explanation.asset_context}</p>
      <p className="text-sm whitespace-pre-line">
        <RichText text={explanation.text} />
      </p>
    </div>
  );
}

function SourceBadge({ explanation }: { explanation: Explanation }) {
  const fromModel = explanation.source === "model";
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
      <Badge variant={fromModel ? "ok" : "neutral"}>
        {fromModel ? (
          <Bot className="mr-1 size-3" aria-hidden />
        ) : (
          <FileText className="mr-1 size-3" aria-hidden />
        )}
        {fromModel ? "Model lokalny" : "Wersja automatyczna"}
      </Badge>
      <span>{explanation.label}</span>
      {explanation.created_at && <span>· {formatDateTime(explanation.created_at)}</span>}
    </div>
  );
}

export function ExplanationPanel({ findingId }: { findingId: string }) {
  const [audience, setAudience] = useState<Audience>("operational");
  const [live, setLive] = useState<Live>({ state: "idle" });
  const [notice, setNotice] = useState<string | null>(null);
  const close = useRef<(() => void) | null>(null);
  const queryClient = useQueryClient();

  const status = useQuery({ queryKey: ["llm-status"], queryFn: api.llmStatus, staleTime: 30_000 });
  const explanation = useQuery({
    queryKey: ["explanation", findingId, audience],
    queryFn: () => api.explanation(findingId, audience),
  });

  useEffect(() => () => close.current?.(), []);

  function reset(next: Audience) {
    close.current?.();
    setLive({ state: "idle" });
    setNotice(null);
    setAudience(next);
  }

  async function generate(regenerate: boolean) {
    setNotice(null);
    setLive({ state: "running", text: "", note: "W kolejce do modelu…" });
    try {
      const job = await api.requestExplanation(findingId, {
        audience,
        regenerate,
      });
      if (!job.job_id) {
        setLive({ state: "idle" });
        setNotice(job.detail);
        if (job.explanation) {
          queryClient.setQueryData(["explanation", findingId, audience], job.explanation);
        }
        return;
      }
      close.current = api.explanationEvents(job.job_id, (event) => {
        if (event.type === "start") {
          setLive({ state: "running", text: "", note: "Model pisze…" });
        } else if (event.type === "token") {
          setLive((current) =>
            current.state === "running" ? { ...current, text: current.text + event.text } : current,
          );
        } else if (event.type === "retry") {
          setLive({
            state: "running",
            text: "",
            note: "Odpowiedź nie spełniła wymagań formy, model próbuje drugi raz…",
          });
        } else if (event.type === "done") {
          setLive({ state: "idle" });
          void queryClient.invalidateQueries({ queryKey: ["explanation", findingId, audience] });
        } else if (event.type === "error") {
          setLive({ state: "error", message: event.message });
        }
      });
    } catch (error) {
      setLive({ state: "error", message: error instanceof Error ? error.message : String(error) });
    }
  }

  const data = explanation.data;
  const modelReady = status.data?.available ?? false;
  const running = live.state === "running";

  return (
    <section>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold">Wyjaśnienie</h3>
        <div role="tablist" aria-label="Poziom odbiorcy" className="flex gap-1">
          {AUDIENCES.map((item) => (
            <button
              key={item.value}
              type="button"
              role="tab"
              aria-selected={audience === item.value}
              title={item.hint}
              onClick={() => reset(item.value)}
              className={cn(
                "rounded-md px-2 py-1 text-xs",
                audience === item.value
                  ? "bg-foreground text-background"
                  : "bg-muted text-muted-foreground hover:text-foreground",
              )}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-3 rounded-md border border-border p-3">
        {running ? (
          <div aria-live="polite" className="space-y-2">
            <p className="text-xs text-muted-foreground">{live.note}</p>
            <p className="text-sm whitespace-pre-line">
              <RichText text={live.text} />
              <span className="ml-0.5 inline-block h-4 w-1.5 animate-pulse bg-foreground align-middle" />
            </p>
            <p className="text-xs text-muted-foreground">
              Podgląd na żywo. Tekst pojawi się na stałe dopiero po automatycznej kontroli faktów.
            </p>
          </div>
        ) : data ? (
          <>
            <ExplanationText explanation={data} />
            <SourceBadge explanation={data} />
          </>
        ) : (
          <p className="text-sm text-muted-foreground">
            {explanation.error ? "Nie udało się pobrać wyjaśnienia." : "Wczytywanie…"}
          </p>
        )}

        {live.state === "error" && <p className="text-sm text-red-700">{live.message}</p>}
        {notice && <p className="text-sm text-muted-foreground">{notice}</p>}

        <div className="flex flex-wrap items-center gap-2">
          {data && !data.cached && (
            <Button
              size="sm"
              onClick={() => void generate(false)}
              disabled={running || !modelReady}
            >
              <Sparkles className="mr-1 size-4" aria-hidden />
              Wygeneruj modelem lokalnym
            </Button>
          )}
          {data?.cached && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => void generate(true)}
              disabled={running || !modelReady}
            >
              <RefreshCw className="mr-1 size-4" aria-hidden />
              Wygeneruj ponownie
            </Button>
          )}
          {status.data && !modelReady && (
            <span className="text-xs text-muted-foreground">
              Model niedostępny: {status.data.detail}. System działa dalej na wyjaśnieniach z
              szablonu.
            </span>
          )}
        </div>
        <p className="text-xs text-muted-foreground">
          Model nie decyduje o niczym: dostaje tylko fakty z bazy, a każdą odpowiedź sprawdza kod
          (identyfikatory CVE, wersje, daty i polecenia muszą pochodzić z faktów).
        </p>
      </div>
    </section>
  );
}
