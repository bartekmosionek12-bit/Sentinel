/** Wspólne elementy stron obu konsol. */

/** Tytuł strony; opis jest w podpowiedzi (title), bez tłumaczeń nad każdym widokiem. */
export function PageHeader({ title, description }: { title: string; description: string }) {
  return (
    <div className="mb-4 border-b border-border pb-3">
      <h1 className="text-xl font-semibold" title={description}>
        {title}
      </h1>
    </div>
  );
}

export function QueryState({
  isPending,
  error,
  empty,
  emptyText,
}: {
  isPending: boolean;
  error: Error | null;
  empty: boolean;
  emptyText: string;
}) {
  if (isPending) return <p className="p-5 text-sm text-muted-foreground">Wczytywanie…</p>;
  if (error)
    return (
      <p className="p-5 text-sm text-red-700">Nie udało się wczytać danych: {error.message}</p>
    );
  if (empty) return <p className="p-5 text-sm text-muted-foreground">{emptyText}</p>;
  return null;
}
