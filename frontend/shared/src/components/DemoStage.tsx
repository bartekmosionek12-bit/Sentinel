/** Scena nagrania demo (moduł 22): Sentek, dymek, podświetlenie elementu i plansza końcowa. */
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { Sentek } from "@shared/components/Sentek";
import { api } from "@shared/lib/api";
import { type DemoRect, type DemoScene, isDemoRecording } from "@shared/lib/demo";
import { asPose } from "@shared/lib/sentek";
import { cn } from "@shared/lib/utils";

declare global {
  interface Window {
    sentinelDemo?: { scene: (scene: DemoScene) => boolean; clear: () => void };
  }
}

function rectOf(selector: string | undefined): DemoRect | null {
  if (!selector) return null;
  const element = document.querySelector(selector);
  if (!element) return null;
  element.scrollIntoView({ block: "center" });
  const box = element.getBoundingClientRect();
  return { x: box.left, y: box.top, width: box.width, height: box.height };
}

export function DemoStage() {
  const recording = isDemoRecording();
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, enabled: recording });
  const [scene, setScene] = useState<DemoScene | null>(null);
  const [rect, setRect] = useState<DemoRect | null>(null);
  const active = recording && health.data?.demo_mode === true;

  useEffect(() => {
    if (!active) return;
    window.sentinelDemo = {
      // Zwraca false, gdy podświetlanego elementu nie ma w DOM (nagrywarka przerywa wtedy scenę).
      scene: (next) => {
        const box = rectOf(next.highlight);
        setScene(next);
        setRect(box);
        return !next.highlight || box !== null;
      },
      clear: () => {
        setScene(null);
        setRect(null);
      },
    };
    document.documentElement.dataset.demoReady = "1";
    return () => {
      delete window.sentinelDemo;
      delete document.documentElement.dataset.demoReady;
    };
  }, [active]);

  // Podświetlenie podąża za elementem, gdy strona się przewinie albo dociągnie dane.
  useEffect(() => {
    if (!scene?.highlight) return;
    const timer = window.setInterval(() => {
      const element = document.querySelector(scene.highlight ?? "");
      if (!element) return;
      const box = element.getBoundingClientRect();
      setRect({ x: box.left, y: box.top, width: box.width, height: box.height });
    }, 250);
    return () => window.clearInterval(timer);
  }, [scene]);

  if (!active || !scene) return null;
  const side = scene.side ?? "right";
  if (scene.endCard)
    return (
      <div
        className="fixed inset-0 z-[100] flex flex-col items-center justify-center gap-6 bg-background px-16 text-center text-foreground"
        data-demo="end-card"
      >
        <Sentek pose={asPose(scene.pose)} size={200} />
        <h1 className="text-6xl font-bold">{scene.endCard.title}</h1>
        <div className="h-1 w-40 bg-primary" />
        {scene.endCard.lines.map((line) => (
          <p key={line} className="text-3xl text-muted-foreground">
            {line}
          </p>
        ))}
      </div>
    );
  const pad = 10;
  return (
    <div className="pointer-events-none fixed inset-0 z-[100]" data-demo="stage">
      {rect && (
        <div
          className="absolute rounded-lg border-4 border-primary"
          style={{
            left: rect.x - pad,
            top: rect.y - pad,
            width: rect.width + 2 * pad,
            height: rect.height + 2 * pad,
          }}
        />
      )}
      <div
        className={cn(
          "absolute bottom-40 flex w-56 flex-col gap-2",
          side === "right" ? "right-6 items-end" : "left-6 items-start",
        )}
      >
        {scene.bubble && (
          <p className="rounded-lg border-2 border-primary bg-card px-4 py-3 text-lg leading-snug font-medium text-foreground">
            {scene.bubble}
          </p>
        )}
        <Sentek pose={asPose(scene.pose)} size={170} />
      </div>
    </div>
  );
}
