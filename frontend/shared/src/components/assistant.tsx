/**
 * Sentek w konsoli (moduł 21): pytania po polsku, odpowiedzi z danych (backend /api/assistant),
 * linki do widoków. Sentek tylko czyta dane: nie skanuje i nie zmienia ustawień.
 * Przywrócony z historii (usunięty w 7851222) i dopasowany do obecnego wyglądu konsoli.
 */
import { useMutation } from "@tanstack/react-query";
import { MessageCircle, Send, X, Zap } from "lucide-react";
import { type FormEvent, type ReactNode, useEffect, useRef, useState } from "react";
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
/** Szybkie akcje: zawsze pod ręką nad polem pytania. */
const QUICK = [
  "Podsumuj krytyczne zagrożenia",
  "Wskaż hosty Shadow IT",
  "Sprawdź stan feedów i systemu",
  "Zaproponuj bezpieczny skan L1",
  "Co się zmieniło od ostatniego skanu?",
  "Gdzie są panele administracyjne?",
];

/** Linki w Markdownie z odpowiedzi ([etykieta](/ścieżka)) jako linki do widoków konsoli.
 *  Tylko ścieżki wewnętrzne (zaczynające się od „/”); reszta zostaje zwykłym tekstem. */
function RichLine({ text }: { text: string }) {
  const parts: ReactNode[] = [];
  const pattern = /\[([^\]]+)\]\((\/[^)\s]*)\)/g;
  let last = 0;
  for (const match of text.matchAll(pattern)) {
    const index = match.index ?? 0;
    if (index > last) parts.push(text.slice(last, index));
    parts.push(
      <Link key={index} className="font-medium text-primary underline" to={match[2] ?? "/"}>
        {match[1]}
      </Link>,
    );
    last = index + match[0].length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return <p>{parts}</p>;
}

function Typing() {
  return (
    <div
      className="mr-4 inline-flex items-center gap-2 rounded-sm border border-border bg-muted px-3 py-2"
      role="status"
      aria-label="Sentek sprawdza dane"
    >
      {[0, 1, 2].map((dot) => (
        <span
          key={dot}
          className="sentek-dot size-1.5 rounded-full bg-primary"
          style={{ animationDelay: `${dot * 0.15}s` }}
        />
      ))}
      <span className="text-xs text-muted-foreground">Sentek sprawdza dane…</span>
    </div>
  );
}

type Message =
  | { id: number; from: "user"; text: string }
  | { id: number; from: "sentek"; answer: AssistantAnswer };

function AnswerBubble({ answer }: { answer: AssistantAnswer }) {
  return (
    <div className="space-y-2 rounded-sm border border-border bg-muted px-3 py-2 text-sm">
      {answer.text.map((line, index) => (
        <RichLine key={index} text={line} />
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
  const suggestions = (last && last.from === "sentek" ? last.answer.suggestions : []).filter(
    (text) => !QUICK.includes(text),
  );

  if (!open)
    return (
      <div className="fixed right-4 bottom-4 z-40 flex flex-row-reverse items-end">
        {/* Sama postać, bez ramki i tła. Chmurka i powiększenie tylko po najechaniu
            (albo fokusie klawiaturą) na Sentka. Przycisk jest pierwszy w DOM (peer),
            a flex-row-reverse stawia chmurkę po jego lewej stronie. */}
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="peer group cursor-pointer appearance-none border-0 bg-transparent p-0 outline-none [-webkit-tap-highlight-color:transparent]"
          aria-label="Zapytaj Sentka"
          data-demo="sentek-button"
        >
          <span className="sentek-float block">
            <Sentek
              pose="wave"
              size={128}
              className="shrink-0 origin-bottom drop-shadow-lg transition-transform duration-300 ease-out group-hover:scale-115 group-focus-visible:scale-115"
            />
          </span>
        </button>
        <div
          aria-hidden
          className="pointer-events-none relative mr-1 mb-20 max-w-56 translate-x-3 scale-90 rounded-2xl bg-white px-4 py-2.5 text-sm font-medium text-slate-900 opacity-0 shadow-lg transition-all duration-300 ease-out peer-hover:translate-x-0 peer-hover:scale-100 peer-hover:opacity-100 peer-focus-visible:translate-x-0 peer-focus-visible:scale-100 peer-focus-visible:opacity-100"
        >
          Cześć! Mogę Ci pomóc. Kliknij i zapytaj o zagrożenia, hosty albo stan systemu.
          <span className="absolute -right-1.5 bottom-3 size-3 rotate-45 bg-white" />
        </div>
      </div>
    );

  return (
    <section
      className="fixed right-4 bottom-4 z-40 flex max-h-[min(640px,85vh)] w-[min(400px,calc(100vw-2rem))] flex-col rounded-sm border border-border bg-card"
      aria-label="Asystent Sentek"
      data-demo="sentek-panel"
    >
      <header className="flex items-center gap-3 border-b border-border p-3">
        <Sentek pose={pose} size={96} className="shrink-0" />
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
            Cześć! Pytaj o zagrożenia i katalog KEV, hosty i otwarte porty, stan skanów i
            feedów albo terminy napraw. Szybkie akcje masz pod spodem.
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
        {ask.isPending && <Typing />}
        {ask.error && (
          <p role="alert" className="text-sm text-red-700">
            {ask.error.message}
          </p>
        )}
        <div ref={end} />
      </div>
      <div className="flex flex-wrap gap-1.5 border-t border-border px-3 pt-2">
        {QUICK.map((text) => (
          <button
            key={text}
            type="button"
            onClick={() => submit(text)}
            disabled={ask.isPending}
            className="inline-flex items-center gap-1 rounded-sm border border-primary/40 bg-primary/10 px-2 py-0.5 text-xs hover:border-primary disabled:opacity-50"
          >
            <Zap className="size-3 text-amber-400" aria-hidden />
            {text}
          </button>
        ))}
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
