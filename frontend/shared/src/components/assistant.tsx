/**
 * Dymek Sentka (moduł 21): pytania po polsku, odpowiedzi z danych (backend), linki do widoków
 * i propozycje akcji. Prośbę o skan wysyła dopiero człowiek przyciskiem; Sentek sam nic nie robi.
 */
import { useMutation } from "@tanstack/react-query";
import { MessageCircle, Send, X } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { Sentek, type SentekPose } from "@shared/components/Sentek";
import { Button } from "@shared/components/ui/button";
import { Input } from "@shared/components/ui/input";
import {
  api,
  type AssistantAction,
  type AssistantAnswer,
} from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";
import { isDemoRecording } from "@shared/lib/demo";
import { usePseudonyms } from "@shared/lib/privacy";
import { asPose, setSentekEnabled, useSentekEnabled } from "@shared/lib/sentek";
import { cn } from "@shared/lib/utils";

const DISCLAIMER =
  "Sentek pomaga czytać dane. Nie skanuje sieci i nie zmienia ustawień.";
const START = [
  "Co jest teraz najgroźniejsze?",
  "Ile mamy nieznanych urządzeń?",
  "Do kiedy trzeba naprawić zagrożenia?",
  "Co to jest KEV?",
];

type Message =
  | { id: number; from: "user"; text: string }
  | { id: number; from: "sentek"; answer: AssistantAnswer };

function ScanProposal({ action }: { action: AssistantAction }) {
  const send = useMutation({
    mutationFn: () =>
      api.requestScan(
        action.scope_kind ?? "organization",
        action.scope_ref ?? null,
        `Prośba złożona w rozmowie z Sentkiem (${action.label ?? "zakres"})`,
      ),
  });
  if (send.isSuccess)
    return (
      <p className="text-xs text-emerald-800" role="status">
        Prośba wysłana. Czeka na zatwierdzenie administratora.
      </p>
    );
  return (
    <div className="space-y-1">
      <Button
        size="sm"
        onClick={() => send.mutate()}
        disabled={send.isPending}
        data-demo="sentek-scan"
      >
        Wyślij prośbę o skanowanie
      </Button>
      {send.error && (
        <p role="alert" className="text-xs text-red-700">
          {send.error.message}
        </p>
      )}
    </div>
  );
}

function AnswerBubble({
  answer,
  onTour,
}: {
  answer: AssistantAnswer;
  onTour?: () => void;
}) {
  return (
    <div className="space-y-2 rounded-sm border border-border bg-muted px-3 py-2 text-sm">
      {answer.text.map((line, index) => (
        <p key={index}>{line}</p>
      ))}
      {answer.freshness && (
        <p className="text-xs text-muted-foreground">{answer.freshness}</p>
      )}
      {answer.links.length > 0 && (
        <ul className="flex flex-wrap gap-x-3 gap-y-1">
          {answer.links.map((link) => (
            <li key={link.to}>
              <Link className="text-xs font-medium underline" to={link.to}>
                {link.label}
              </Link>
            </li>
          ))}
        </ul>
      )}
      {answer.action?.kind === "scan_request" && (
        <ScanProposal action={answer.action} />
      )}
      {answer.action?.kind === "tour" && onTour && (
        <Button size="sm" variant="outline" onClick={onTour}>
          Uruchom samouczek
        </Button>
      )}
    </div>
  );
}

export function SentekAssistant({ onTour }: { onTour?: () => void }) {
  const { can } = useAuth();
  const enabled = useSentekEnabled();
  const pseudonyms = usePseudonyms();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const nextId = useRef(1);
  const end = useRef<HTMLDivElement>(null);
  const ask = useMutation({
    mutationFn: (question: string) => api.assistant(question, pseudonyms),
    onSuccess: (answer) =>
      setMessages((list) => [
        ...list,
        { id: nextId.current++, from: "sentek", answer },
      ]),
  });
  useEffect(() => {
    end.current?.scrollIntoView?.({ block: "end" });
  }, [messages, ask.isPending]);

  // W nagraniu demo Sentek występuje na scenie (DemoStage), nie w dymku.
  if (!enabled || !can("assistant:use") || isDemoRecording()) return null;

  const submit = (question: string) => {
    const text = question.trim();
    if (!text || ask.isPending) return;
    setMessages((list) => [
      ...list,
      { id: nextId.current++, from: "user", text },
    ]);
    setDraft("");
    ask.mutate(text);
  };
  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    submit(draft);
  };
  const last = [...messages].reverse().find((m) => m.from === "sentek");
  const pose: SentekPose = ask.isPending
    ? "talk"
    : last && last.from === "sentek"
      ? asPose(last.answer.pose)
      : "wave";
  const suggestions =
    last && last.from === "sentek" ? last.answer.suggestions : START;

  if (!open)
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="fixed right-4 bottom-4 z-40 flex max-w-[calc(100vw-2rem)] items-center gap-2 rounded-sm border border-border bg-card py-1 pr-4 pl-1 hover:border-primary"
        aria-label="Zapytaj Sentka"
        data-demo="sentek-button"
      >
        <Sentek pose="wave" size={100} className="shrink-0" />
        <span className="text-sm font-medium">Zapytaj Sentka</span>
      </button>
    );

  return (
    <section
      className="fixed right-4 bottom-4 z-40 flex max-h-[min(680px,90vh)] w-[min(420px,calc(100vw-2rem))] flex-col rounded-sm border border-border bg-card"
      aria-label="Asystent Sentek"
      data-demo="sentek-panel"
    >
      <header className="flex items-center gap-3 border-b border-border p-3">
        <Sentek pose={pose} size={112} className="shrink-0" />
        <div className="min-w-0 flex-1">
          <h2 className="font-semibold">Sentek</h2>
          <p className="text-xs text-muted-foreground">{DISCLAIMER}</p>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setOpen(false)}
          aria-label="Zamknij Sentka"
        >
          <X className="size-4" aria-hidden />
        </Button>
      </header>
      <div className="flex-1 space-y-3 overflow-y-auto p-3" aria-live="polite">
        {messages.length === 0 && (
          <p className="text-sm">
            Cześć! Pytaj o zagrożenia, urządzenia, terminy napraw albo znaczenie
            skrótów.
          </p>
        )}
        {messages.map((message) =>
          message.from === "user" ? (
            <p
              key={message.id}
              className="ml-8 rounded-lg rounded-tr-none bg-sky-100 px-3 py-2 text-sm text-sky-950"
            >
              {message.text}
            </p>
          ) : (
            <div key={message.id} className="mr-4">
              <AnswerBubble answer={message.answer} onTour={onTour} />
            </div>
          ),
        )}
        {ask.isPending && (
          <p className="text-sm text-muted-foreground">Sentek sprawdza dane…</p>
        )}
        {ask.error && (
          <p role="alert" className="text-sm text-red-700">
            {ask.error.message}
          </p>
        )}
        <div ref={end} />
      </div>
      <div className="flex flex-wrap gap-1.5 border-t border-border px-3 pt-2">
        {suggestions.map((text) => (
          <button
            key={text}
            type="button"
            onClick={() => submit(text)}
            className="rounded-full border border-border px-2.5 py-1 text-xs hover:border-sky-300 hover:bg-sky-50"
          >
            {text}
          </button>
        ))}
      </div>
      <form onSubmit={onSubmit} className="flex items-center gap-2 p-3">
        <Input
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder="Zapytaj o stan bezpieczeństwa"
          aria-label="Pytanie do Sentka"
          maxLength={500}
          data-demo="sentek-input"
        />
        <Button
          type="submit"
          size="sm"
          disabled={!draft.trim() || ask.isPending}
          aria-label="Wyślij pytanie"
        >
          <Send className="size-4" aria-hidden />
        </Button>
      </form>
    </section>
  );
}

/** Przycisk w nagłówku: włącza i wyłącza Sentka (np. na czas prezentacji). */
export function SentekToggle() {
  const { can } = useAuth();
  const enabled = useSentekEnabled();
  if (!can("assistant:use")) return null;
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={() => setSentekEnabled(!enabled)}
      aria-pressed={enabled}
      title={enabled ? "Wyłącz asystenta Sentek" : "Włącz asystenta Sentek"}
      className={cn(!enabled && "text-muted-foreground")}
    >
      <MessageCircle className="size-4" aria-hidden />
      <span className="hidden lg:inline">
        {enabled ? "Sentek" : "Sentek wyłączony"}
      </span>
    </Button>
  );
}
