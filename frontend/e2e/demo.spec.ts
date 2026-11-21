/**
 * Moduł 22: scenariusz filmu (demo/script.yaml) pasuje do interfejsu. Każda scena z
 * podświetleniem musi znaleźć swój element w trybie nagrywania (`?demo=record`), a plansza
 * końcowa musi się wyświetlić. Dane z e2e/fixtures (fikcyjne, jak demo-lab).
 */
import { readFileSync } from "node:fs";
import path from "node:path";

import { expect, test } from "@playwright/test";
import { parse } from "yaml";

import { stubApi } from "./stub";

interface Scene {
  id: string;
  app: "dashboard" | "admin";
  path: string;
  highlight?: string;
  pose: string;
  side?: "left" | "right";
  bubble?: string;
  then?: { at: number; highlight?: string; bubble?: string };
  end_card?: { title: string; line: string };
}

const SCRIPT = parse(
  readFileSync(path.join(import.meta.dirname, "..", "..", "demo", "script.yaml"), "utf8"),
) as { scenes: Scene[] };

const PORTS = { dashboard: 5174, admin: 5173 };
const DEMO: [RegExp, string][] = [
  [/^\/api\/inbox/, "demo/inbox"],
  [/^\/api\/reports\/[^/?]+$/, "demo/report"],
  [/^\/api\/agent\/tasks/, "demo/agent_tasks"],
  [/^\/api\/agent\/leases/, "demo/agent_leases"],
  [/^\/api\/agent\/tests/, "demo/agent_tests"],
  [/^\/api\/agent\/status/, "demo/agent_status"],
  [/^\/api\/agent\/configs/, "demo/agent_configs"],
];

for (const scene of SCRIPT.scenes) {
  test(`scena „${scene.id}” ma swój element w trybie nagrywania`, async ({ page }) => {
    await stubApi(page, { app: scene.app, extra: DEMO });
    // Raport otwiera nagrywarka kliknięciem; tu od razu jego adres.
    const where = scene.id === "raport" ? "/raporty/zd-1" : scene.path;
    await page.goto(`http://localhost:${PORTS[scene.app]}/${scene.app}${where}?demo=record`);
    await page.waitForFunction(() => Boolean(window.sentinelDemo));
    const targets = [scene.highlight, scene.then?.highlight].filter(Boolean) as string[];
    for (const selector of targets) {
      await page.locator(selector).first().waitFor({ timeout: 10_000 });
      const found = await page.evaluate(
        ([selector, scene]) =>
          window.sentinelDemo!.scene({
            highlight: selector,
            pose: scene.pose,
            side: scene.side,
            bubble: scene.bubble,
          }),
        [selector, scene] as const,
      );
      expect(found, selector).toBe(true);
    }
    if (scene.end_card) {
      await page.evaluate(
        (scene) => window.sentinelDemo!.scene({ pose: scene.pose, endCard: scene.end_card }),
        scene,
      );
      await expect(page.locator("[data-demo=end-card]")).toContainText(scene.end_card.line);
    } else {
      if (targets.length === 0) {
        await page.evaluate(
          (scene) => window.sentinelDemo!.scene({ pose: scene.pose, bubble: scene.bubble }),
          scene,
        );
      }
      await expect(page.locator("[data-demo=stage]")).toBeVisible();
    }
    // DEMO_SHOTS=katalog: zrzut każdej sceny (np. do docs/DEMO_GUIDE.md).
    if (process.env.DEMO_SHOTS) {
      await page.waitForTimeout(600);
      await page.screenshot({ path: path.join(process.env.DEMO_SHOTS, `${scene.id}.png`) });
    }
  });
}

test("tryb nagrywania nie działa bez DEMO_MODE", async ({ page }) => {
  await stubApi(page);
  await page.route("**/api/health", (route) =>
    route.fulfill({ json: { status: "ok", demo_mode: false } }),
  );
  await page.goto("http://localhost:5174/dashboard/?demo=record");
  await expect(page.getByText("Stan bezpieczeństwa").first()).toBeVisible();
  expect(await page.evaluate(() => Boolean(window.sentinelDemo))).toBe(false);
});
