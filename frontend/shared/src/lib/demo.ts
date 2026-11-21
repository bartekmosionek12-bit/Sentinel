/**
 * Tryb nagrywania demo (moduł 22): `?demo=record` w adresie, działa tylko przy DEMO_MODE
 * (sprawdza to DemoStage na podstawie /api/health). Flaga zostaje w sessionStorage, żeby
 * przetrwała nawigację w aplikacji. W tym trybie nie ma samouczka ani pływającego Sentka;
 * scenami steruje scripts/record_demo.mjs przez `window.sentinelDemo`.
 */
const KEY = "sentinel.demo";

export function isDemoRecording(): boolean {
  try {
    if (new URLSearchParams(window.location.search).get("demo") === "record") {
      sessionStorage.setItem(KEY, "record");
      return true;
    }
    return sessionStorage.getItem(KEY) === "record";
  } catch {
    return false;
  }
}

export interface DemoRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface DemoScene {
  pose?: string;
  side?: "left" | "right";
  bubble?: string;
  /** Selektor CSS elementu do podświetlenia (pozycję liczy strona). */
  highlight?: string;
  endCard?: { title: string; line: string };
}
