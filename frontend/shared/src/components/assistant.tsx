/**
 * Sentek w konsoli (moduł 21): pytania po polsku, odpowiedzi z danych (backend /api/assistant),
 * linki do widoków. Sentek tylko czyta dane: nie skanuje i nie zmienia ustawień.
 * Przywrócony z historii (usunięty w 7851222) i dopasowany do obecnego wyglądu konsoli.
 */
import { useMutation } from "@tanstack/react-query";
import { MessageCircle, Send, X } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { Sentek, type SentekPose } from "@shared/components/Sentek";
import { Button } from "@shared/components/ui/button";
import { Input } from "@shared/components/ui/input";
import { api, type AssistantAnswer } from "@shared/lib/api";
import { useAuth } from "@shared/lib/auth-context";
import { isDemoRecording } from "@shared/lib/demo";
import { asPose, setSentekEnabled, useSentekEnabled } from "@shared/lib/sentek";
import { cn } from "@shared/lib/utils";

const DISCLAIMER = "Odpowiada z danych w systemie. Nie skanuje sieci i nie zmienia ustawień.";
const START = [
  "Co jest teraz najgroźniejsze?",
  "Ile mamy nowych hostów?",
  "Do kiedy trzeba naprawić zagrożenia?",
  "Co to jest KEV?",
];

type Message =
  | { id: number; from: "user"; text: string }
  | { id: number; from: "sentek"; answer: AssistantAnswer };

function AnswerBubble({ answer }: { answer: AssistantAnswer }) {
  return (
    <div className="space-y-2 rounded-sm border border-border bg-muted px-3 py-2 text-sm">
      {answer.text.map((line, index) => (
        <p key={index}>{line}</p>
      ))}
      {answer.freshness && <p className="text-xs text-muted-foreground">{answer.freshness}</p>}
      {answer.links.length > 0 && (
        <ul className="flex flex-wrap gap-x-3 gap-y-1">
          {answer.links.map((link) => (
            <li key={link.to}>
              <Link className="text-xs font-medium text-primary underline" to={link.to}>
                {link.label}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function SentekAssistant() {
  const { can } = useAuth();
  const enabled = useSentekEnabled();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const nextId = useRef(1);
  const end = useRef<HTMLDivElement>(null);
  const ask = useMutation({
    mutationFn: (question: string) => api.assistant(question),
    onSuccess: (answer) =>
      setMessages((list) => [...list, { id: nextId.current++, from: "sentek", answer }]),
  });
  useEffect(() => {
    end.current?.scrollIntoView?.({ block: "end" });
  }, [messages, ask.isPending]);

  // W nagraniu filmu Sentek występuje na scenie (DemoStage), nie w okienku.
  if (!enabled || !can("assistant:use") || isDemoRecording()) return null;

  const submit = (question: string) => {
    const text = question.trim();
    if (!text || ask.isPending) return;
    setMessages((list) => [...list, { id: nextId.current++, from: "user", text }]);
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
  const suggestions = last && last.from === "sentek" ? last.answer.suggestions : START;

  if (!open)
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="fixed right-4 bottom-4 z-40 flex items-center gap-2 rounded-sm border border-border bg-card py-1 pr-3 pl-1 hover:border-primary"
        aria-label="Zapytaj Sentka"
        data-demo="sentek-button"
      >
        <Sentek pose="wave" size={44} />
        <span className="text-sm font-medium">Zapytaj Sentka</span>
      </button>
    );

  return (
    <section
      className="fixed right-4 bottom-4 z-40 flex max-h-[min(640px,85vh)] w-[min(400px,calc(100vw-2rem))] flex-col rounded-sm border border-border bg-card"
      aria-label="Asystent Sentek"
      data-demo="sentek-panel"
    >
      <header className="flex items-center gap-3 border-b border-border p-3">
        <Sentek pose={pose} size={52} />
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
            Cześć! Pytaj o zagrożenia, hosty, terminy napraw albo znaczenie skrótów.
          </p>
        )}
        {messages.map((message) =>
          message.from === "user" ? (
            <p
              key={message.id}
              className="ml-8 rounded-sm border border-primary/40 bg-primary/10 px-3 py-2 text-sm"
            >
              {message.text}
            </p>
          ) : (
            <div key={message.id} className="mr-4">
              <AnswerBubble answer={message.answer} />
            </div>
          ),
        )}
        {ask.isPending && <p className="text-sm text-muted-foreground">Sentek sprawdza dane…</p>}
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
            className="rounded-sm border border-border px-2 py-0.5 text-xs hover:border-primary"
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
      <span className="hidden lg:inline">{enabled ? "Sentek" : "Sentek wyłączony"}</span>
    </Button>
  );
}
