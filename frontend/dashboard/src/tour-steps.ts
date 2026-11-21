/**
 * Samouczek konsoli menedżera (moduł 21, §25.2): przy pierwszym logowaniu i na żądanie.
 * Kroki przechodzą między ekranami; każdy krok czeka na swój element (maks. 4 s), a gdy go
 * nie ma (np. brak danych), pokazuje opis bez podświetlenia. Klawiatura: strzałki i Esc.
 */
import { driver, type Driver } from "driver.js";
import "driver.js/dist/driver.css";
import type { NavigateFunction } from "react-router-dom";

export interface TourStep {
  path: string;
  selector: string;
  title: string;
  text: string;
}

export const TOUR: TourStep[] = [
  {
    path: "/",
    selector: '[data-demo="headline"]',
    title: "Stan w jednym zdaniu",
    text: "Kolor i zdanie liczy kod z ostatniego raportu, nie model językowy. Czerwone znaczy: działaj dziś.",
  },
  {
    path: "/",
    selector: '[data-demo="tile-unknown"]',
    title: "Nieznane urządzenia",
    text: "Urządzenia widziane w sieci, których nie ma w CMDB, AD ani MDM. Mogą być shadow IT.",
  },
  {
    path: "/",
    selector: '[data-demo="units"]',
    title: "Działy",
    text: "Gdzie są urządzenia i zagrożenia. Kliknij dział, żeby zobaczyć jego sprzęt i właścicieli.",
  },
  {
    path: "/nieznane",
    selector: '[data-demo="device-table"]',
    title: "Nieznane i niepotwierdzone",
    text: "Lista do wyjaśnienia z działem IT. Potwierdza je zespół bezpieczeństwa.",
  },
  {
    path: "/urzadzenia",
    selector: '[data-demo="device-table"]',
    title: "Karta urządzenia",
    text: "Kliknij nazwę urządzenia: zobaczysz właściciela, dział, źródła danych i otwarte zagrożenia.",
  },
  {
    path: "/mapa",
    selector: '[data-demo="map"]',
    title: "Mapa organizacji",
    text: "Działy i ich urządzenia na jednym obrazie. Kolor to najwyższe ryzyko, przerywana ramka to urządzenie nieznane.",
  },
  {
    path: "/skrzynka",
    selector: '[data-demo="inbox"]',
    title: "Skrzynka",
    text: "Tu trafiają raporty: pięć pytań prostym językiem, a szczegóły techniczne są zwinięte.",
  },
  {
    path: "/",
    selector: '[data-demo="current-picture"]',
    title: "Aktualny obraz",
    text: "Raport z bieżącego stanu w kilka sekund, bez skanowania. Gdy dane są stare, poproś o nowe skanowanie.",
  },
  {
    path: "/",
    selector: '[data-demo="sentek-button"]',
    title: "Sentek",
    text: "Zapytaj po polsku, np. „Co jest teraz najgroźniejsze?”. Sentek czyta dane, ale nie skanuje i nie zmienia ustawień.",
  },
];

function waitFor(selector: string, timeoutMs = 4000): Promise<Element | null> {
  return new Promise((resolve) => {
    const started = Date.now();
    const tick = () => {
      const element = document.querySelector(selector);
      if (element || Date.now() - started > timeoutMs) resolve(element);
      else window.setTimeout(tick, 100);
    };
    tick();
  });
}

const doneKey = (user: string) => `sentinel.tour.done.${user}`;

function markDone(user: string): void {
  try {
    localStorage.setItem(doneKey(user), "1");
  } catch {
    // bez localStorage samouczek pokaże się przy kolejnym wejściu: to nie błąd
  }
}

export function wasDone(user: string): boolean {
  try {
    return localStorage.getItem(doneKey(user)) === "1";
  } catch {
    return true;
  }
}

export function runTour(navigate: NavigateFunction, user: string, steps = TOUR): Driver {
  const tour = driver({
    animate: false,
    allowKeyboardControl: false,
    overlayOpacity: 0.45,
    stagePadding: 6,
    popoverClass: "sentinel-tour",
    nextBtnText: "Dalej",
    prevBtnText: "Wstecz",
    doneBtnText: "Zakończ",
    progressText: "{{current}} z {{total}}",
    showProgress: true,
  });
  let index = 0;
  // Klawiatura: driver.js w trybie pojedynczego podświetlenia nie przewija kroków sam.
  const onKey = (event: KeyboardEvent) => {
    if (event.key === "ArrowRight") void show(index + 1);
    else if (event.key === "ArrowLeft" && index > 0) void show(index - 1);
    else if (event.key === "Escape") finish();
  };
  const finish = () => {
    document.removeEventListener("keydown", onKey);
    tour.destroy();
    markDone(user);
  };
  document.addEventListener("keydown", onKey);
  const show = async (next: number) => {
    if (next < 0 || next >= steps.length) {
      finish();
      return;
    }
    index = next;
    const step = steps[next];
    if (!step) return;
    navigate(step.path);
    const element = await waitFor(step.selector);
    tour.setConfig({
      ...tour.getConfig(),
      showProgress: true,
      onNextClick: () => void show(index + 1),
      onPrevClick: () => void show(index - 1),
      onCloseClick: finish,
    });
    tour.highlight({
      element: element ?? undefined,
      popover: {
        title: step.title,
        description: step.text,
        showButtons: ["next", "previous", "close"],
        nextBtnText: next === steps.length - 1 ? "Zakończ" : "Dalej",
        progressText: `${next + 1} z ${steps.length}`,
        showProgress: true,
      },
    });
  };
  void show(0);
  return tour;
}

