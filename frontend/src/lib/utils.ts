import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

const dateTime = new Intl.DateTimeFormat("pl-PL", {
  dateStyle: "medium",
  timeStyle: "medium",
});

export function formatDateTime(iso: string): string {
  return dateTime.format(new Date(iso));
}

const dateOnly = new Intl.DateTimeFormat("pl-PL", { dateStyle: "medium" });

export function formatDate(iso: string): string {
  return dateOnly.format(new Date(iso));
}

/** Imię operatora dopisywane do decyzji, dopóki nie ma logowania (osobne zadanie). */
const OPERATOR_KEY = "sentinel.operator";

export function getOperator(): string {
  try {
    return window.localStorage.getItem(OPERATOR_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setOperator(name: string): void {
  try {
    window.localStorage.setItem(OPERATOR_KEY, name);
  } catch {
    // brak dostępu do pamięci przeglądarki: imię obowiązuje do odświeżenia strony
  }
}
