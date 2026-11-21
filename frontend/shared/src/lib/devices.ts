import type { OrgPerson } from "@shared/lib/api";

/** Osoby przypisane do urządzenia jako tekst; osoby, które odeszły, są oznaczone. */
export function people(list: OrgPerson[]): string {
  return list
    .map((p) => (p.active ? p.display_name : `${p.display_name} (już nie pracuje)`))
    .join(", ");
}
