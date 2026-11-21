/**
 * Przełącznik „Pokaż pseudonimy” (ARCHITECTURE §15): zamiast nazwisk „Pracownik #N”, np. na
 * czas prezentacji. Ustawienie tylko dla tej przeglądarki; o tym, kto w ogóle widzi nazwiska,
 * decyduje backend (`personal_data:view`).
 */
import { useSyncExternalStore } from "react";

const KEY = "sentinel.pseudonyms";
const listeners = new Set<() => void>();

function read(): boolean {
  try {
    return localStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}

export function setPseudonyms(value: boolean): void {
  try {
    localStorage.setItem(KEY, value ? "1" : "0");
  } catch {
    // tryb prywatny albo zablokowany storage: przełącznik działa do odświeżenia strony
  }
  current = value;
  listeners.forEach((listener) => listener());
}

let current = read();

export function usePseudonyms(): boolean {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}
