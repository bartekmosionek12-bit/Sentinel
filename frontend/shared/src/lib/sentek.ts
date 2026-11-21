/** Włącznik Sentka (moduł 21): asystenta można wyłączyć; ustawienie tylko dla tej przeglądarki. */
import { useSyncExternalStore } from "react";

const KEY = "sentinel.sentek";
const listeners = new Set<() => void>();

function read(): boolean {
  try {
    return localStorage.getItem(KEY) !== "off";
  } catch {
    return true;
  }
}

let current = read();

export function setSentekEnabled(value: boolean): void {
  try {
    localStorage.setItem(KEY, value ? "on" : "off");
  } catch {
    // zablokowany storage: ustawienie działa do odświeżenia strony
  }
  current = value;
  listeners.forEach((listener) => listener());
}

export function useSentekEnabled(): boolean {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}

export type SentekPose =
  | "idle"
  | "talk"
  | "wave"
  | "point_left"
  | "point_right"
  | "surprised"
  | "thumbs_up";

export const SENTEK_POSES: SentekPose[] = [
  "idle",
  "talk",
  "wave",
  "point_left",
  "point_right",
  "surprised",
  "thumbs_up",
];

const POSES = new Set<string>(SENTEK_POSES);

export function asPose(value: string | undefined): SentekPose {
  return value && POSES.has(value) ? (value as SentekPose) : "talk";
}
