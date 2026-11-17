import { Input } from "@/components/ui/input";

/** Imię osoby podejmującej decyzję. Trafia do dziennika audytu razem z decyzją. */
export function OperatorField({
  value,
  onChange,
}: {
  value: string;
  onChange: (name: string) => void;
}) {
  return (
    <label className="text-xs font-medium">
      Kto decyduje
      <Input
        className="mt-1 block w-56"
        required
        maxLength={255}
        placeholder="imię i nazwisko"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  );
}
