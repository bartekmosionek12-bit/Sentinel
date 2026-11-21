/** Wspólne elementy stron obu konsol. */

export function PageHeader({ title, description }: { title: string; description: string }) {
  return (
    <div className="mb-6">
      <h1 className="text-2xl font-bold">{title}</h1>
      <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{description}</p>
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
