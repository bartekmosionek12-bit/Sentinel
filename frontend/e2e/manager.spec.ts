/** Konsola menedżera (moduł 21): samouczek, Sentek, mapa i prośba o skan w kolejce admina. */
import { expect, test } from "@playwright/test";

import { stubApi } from "./stub";

const DASHBOARD = "http://localhost:5174/dashboard";
const ADMIN = "http://localhost:5173/admin";

test("samouczek startuje przy pierwszym logowaniu i przechodzi wszystkie kroki", async ({ page }) => {
  await stubApi(page, { tourDone: false });
  await page.goto(`${DASHBOARD}/`);
  const title = page.locator(".driver-popover-title");
  await expect(title).toHaveText("Stan w jednym zdaniu");
  const seen = [await title.textContent()];
  for (let step = 1; step < 9; step += 1) {
    await page.keyboard.press("ArrowRight");
    await expect(title).not.toHaveText(seen[seen.length - 1] ?? "");
    seen.push(await title.textContent());
  }
  expect(seen).toContain("Mapa organizacji");
  expect(seen.at(-1)).toBe("Sentek");
  await page.keyboard.press("Escape");
  await expect(page.locator(".driver-popover")).toHaveCount(0);
  expect(await page.evaluate(() => localStorage.getItem("sentinel.tour.done.manager"))).toBeTruthy();
});

test("Sentek odpowiada na trzy rodzaje pytań i tylko proponuje skan", async ({ page }) => {
  const sent = await stubApi(page);
  await page.goto(`${DASHBOARD}/`);
  await page.getByRole("button", { name: "Zapytaj Sentka" }).click();
  const panel = page.getByRole("region", { name: "Asystent Sentek" });
  await expect(panel).toContainText("Nie skanuje sieci i nie zmienia ustawień");

  await panel.getByRole("button", { name: "Co jest teraz najgroźniejsze?" }).click();
  await expect(panel).toContainText("CVE-2021-42013");
  await expect(panel.getByRole("link", { name: "Wszystkie zagrożenia" })).toBeVisible();

  await panel.getByRole("button", { name: "Ile mamy nieznanych urządzeń?" }).click();
  await expect(panel).toContainText("DESKTOP-7Q2KD1");

  await panel.getByLabel("Pytanie do Sentka").fill("Poproś o skanowanie działu IT");
  await panel.getByLabel("Pytanie do Sentka").press("Enter");
  await expect(panel).toContainText("Sam nie skanuję");
  // Do kliknięcia nic nie trafia do kolejki skanów.
  expect(sent.filter((s) => s.path === "/api/scan-requests")).toHaveLength(0);
  await panel.getByRole("button", { name: "Wyślij prośbę o skanowanie" }).click();
  await expect(panel).toContainText("Czeka na zatwierdzenie administratora");
  const request = sent.find((s) => s.path === "/api/scan-requests");
  expect(request?.body).toMatchObject({ scope_kind: "unit" });

  await panel.getByLabel("Pytanie do Sentka").fill("Wyłącz serwer web-01");
  await panel.getByLabel("Pytanie do Sentka").press("Enter");
  await expect(panel).toContainText("Tego nie zrobię");
});

test("Sentka można wyłączyć w nagłówku", async ({ page }) => {
  await stubApi(page);
  await page.goto(`${DASHBOARD}/`);
  await expect(page.getByRole("button", { name: "Zapytaj Sentka" })).toBeVisible();
  await page.getByTitle("Wyłącz asystenta Sentek").click();
  await expect(page.getByRole("button", { name: "Zapytaj Sentka" })).toHaveCount(0);
});

test("mapa pokazuje urządzenia i filtruje te z zagrożeniami", async ({ page }) => {
  await stubApi(page);
  await page.goto(`${DASHBOARD}/mapa`);
  await expect(page.locator("[data-demo=map] canvas").first()).toBeVisible();
  await expect(page.getByText("38 urządzeń")).toBeVisible();
  await page.getByLabel("Tylko z zagrożeniami i nieznane").check();
  await expect(page.getByText(/^\d urządzeń$|^\d urządzenia$/)).toBeVisible();
});

test("prośba menedżera czeka w kolejce admina i da się ją zatwierdzić", async ({ page }) => {
  const sent = await stubApi(page, { app: "admin" });
  await page.goto(`${ADMIN}/skany`);
  await expect(page.getByText("cała organizacja").first()).toBeVisible();
  await page.getByRole("button", { name: "Zatwierdź i skanuj" }).first().click();
  await expect.poll(() => sent.some((s) => s.path.endsWith("/decision"))).toBe(true);
  const decision = sent.find((s) => s.path.endsWith("/decision"));
  expect(decision?.body).toMatchObject({ approve: true });
});
