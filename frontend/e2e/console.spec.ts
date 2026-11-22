/** Konsola zespołu IT: menu zależne od roli, role i użytkownicy, karta hosta (P1, #30). */
import { readFileSync } from "node:fs";

import { expect, test } from "@playwright/test";

import { stubApi } from "./stub";

const nav = (page: import("@playwright/test").Page) =>
  page.getByRole("navigation", { name: "Nawigacja główna" });

test("administrator widzi macierz ról i tworzy rolę własną bez iam:manage", async ({ page }) => {
  const sent = await stubApi(page);
  // Stary adres /role prowadzi do zakładki „Role i uprawnienia” w jednym panelu IAM.
  await page.goto("/admin/role");
  await expect(page.getByRole("heading", { name: "IAM: role i użytkownicy" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Role i uprawnienia" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  for (const label of ["Administracja", "Dodawanie, usuwanie, modyfikacja", "Odczyt"]) {
    await expect(page.getByRole("columnheader", { name: label, exact: true })).toBeVisible();
  }
  await expect(page.getByRole("columnheader", { name: /audytor/ })).toBeVisible();

  await page.getByLabel("Nazwa (małe litery, cyfry, - i _)").fill("kierownik-zmiany");
  await page.getByLabel("Zacznij od roli").selectOption("viewer");
  await expect(
    page.locator("label", { hasText: "iam:manage" }).getByRole("checkbox"),
  ).toBeDisabled();
  await page.locator("label", { hasText: "findings:update" }).getByRole("checkbox").check();
  await page.getByRole("button", { name: "Zapisz rolę" }).click();
  await expect(page.getByRole("status")).toContainText("Zapisano rolę kierownik-zmiany");

  const put = sent.find((s) => s.method === "PUT");
  expect(put?.path).toBe("/api/iam/roles/kierownik-zmiany");
  const permissions = (put?.body as { permissions: string[] }).permissions;
  expect(permissions).toContain("findings:update");
  expect(permissions).toContain("inventory:read");
  expect(permissions).not.toContain("iam:manage");
});

test("administrator nadaje rolę z konsoli; Administracji nie da się nadać", async ({ page }) => {
  const sent = await stubApi(page);
  await page.goto("/admin/iam");
  const select = page.getByLabel("Rola dla viewer");
  await expect(select.locator("option", { hasText: "Administracja" })).toHaveCount(0);
  await select.selectOption("editor");
  await page
    .getByRole("row", { name: /viewer/ })
    .getByRole("button", { name: "Nadaj" })
    .click();
  await expect.poll(() => sent.find((s) => s.method === "POST")?.body).toEqual({ role: "editor" });
  await expect(page.getByLabel("Rola dla sentinel-agent")).toHaveCount(0);
});

test("rola Odczyt: bez ról, audytu i formularzy zapisu", async ({ page }) => {
  await stubApi(page, { role: "viewer" });
  await page.goto("/admin/zasoby");
  await expect(page.getByRole("heading", { name: "Zasoby" })).toBeVisible();
  await expect(nav(page).getByRole("link", { name: "IAM: role i użytkownicy" })).toHaveCount(0);
  await expect(nav(page).getByRole("link", { name: "Dziennik audytu" })).toHaveCount(0);
  await expect(nav(page).getByRole("link", { name: "Zgodność" })).toHaveCount(0);
  await expect(page.getByText("Dodaj zasób ręcznie")).toHaveCount(0);
  await expect(page.getByText("Import z pliku CSV")).toHaveCount(0);
});

test("karta hosta: usługi, zagrożenia i historia zmian", async ({ page }) => {
  await stubApi(page, { role: "modifier" });
  await page.goto("/admin/zasoby");
  await page.getByRole("link", { name: "web-01" }).click();
  await expect(page).toHaveURL(/\/admin\/zasoby\/2e017b46/);
  await expect(page.getByRole("heading", { name: "web-01" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "Apache httpd", exact: true })).toBeVisible();
  await expect(page.getByText("CVE-2021-42013").first()).toBeVisible();
  await expect(page.getByText("Historia zmian")).toBeVisible();
  await expect(page.getByText("10.20.0.10")).toBeVisible();
});

test("rola Odczyt ma raporty w konsoli; stara Skrzynka przekierowuje do Raportów", async ({
  page,
}) => {
  await stubApi(page, { role: "viewer" });
  await page.goto("/admin/skrzynka");
  await expect(page).toHaveURL(/\/admin\/raporty$/);
  await expect(page.getByRole("heading", { name: "Raporty" })).toBeVisible();
  await expect(nav(page).getByRole("link", { name: "Skrzynka" })).toHaveCount(0);
  await expect(nav(page).getByRole("link", { name: /Mapa/ })).toHaveCount(0);
  await expect(page.getByText("Ocena stanu bezpieczeństwa (2026-11-21)")).toBeVisible();
});

test("własne sygnatury: sprawdzenie i zapis z konsoli, wbudowane tylko do odczytu", async ({
  page,
}) => {
  const sent = await stubApi(page);
  await page.goto("/admin/discovery/sygnatury");
  await expect(page.getByRole("heading", { name: "Sygnatury detekcyjne" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "wordpress-login", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "intranet-demo", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Sprawdź" }).click();
  await expect(page.getByText("Sygnatura „moja-aplikacja” jest poprawna.")).toBeVisible();
  await page.getByRole("button", { name: "Zapisz" }).click();
  await expect(page.getByText("Zapisano „moja-aplikacja”.")).toBeVisible();
  const put = sent.find((s) => s.method === "PUT");
  expect(put?.path).toBe("/api/discovery/signatures/moja-aplikacja");
  expect((put?.body as { yaml: string }).yaml).toContain("kind: technology");
});

test("test sygnatury na zapisanym przebiegu, bez ruchu w sieci", async ({ page }) => {
  const sent = await stubApi(page);
  await page.goto("/admin/discovery/sygnatury");
  await page.getByRole("button", { name: "Testuj wordpress-login" }).click();
  const card = page.locator("[data-demo=signature-test]");
  await expect(card).toContainText("Sprawdzono 12 usług WWW, trafienia: 1");
  await expect(card).toContainText("10.20.4.17");
  await expect(card).toContainText("/wp-login.php → 200");
  await expect(card).toContainText("Sprawdzi je kolejny przebieg");
  const post = sent.find((s) => s.path === "/api/discovery/signatures/test");
  expect(post?.body).toEqual({ id: "wordpress-login" });
});

test("inspekcja sygnatury: reguły, historia trafień i dowody", async ({ page }) => {
  await stubApi(page);
  await page.goto("/admin/discovery/sygnatury");
  await page.getByRole("button", { name: "Inspekcja wordpress-login" }).click();
  const card = page.locator("[data-demo=signature-inspect]");
  await expect(card).toContainText("GET /wp-login.php zwraca 200");
  await expect(card).toContainText("dodatkowe GET przy skanie");
  await expect(card).toContainText("1 z 12 usług");
  await expect(card.locator("[data-demo=signature-history] a")).toHaveCount(2);
  await expect(card).toContainText("10.20.4.17");
});

test("harmonogram discovery: okno czasowe, częstotliwość i wznowienie", async ({ page }) => {
  const sent = await stubApi(page);
  await page.goto("/admin/discovery/harmonogram");
  await expect(page.getByRole("heading", { name: "Harmonogram discovery" })).toBeVisible();
  const row = page.locator("[data-demo=schedule-row]");
  await expect(row).toContainText("Nocny skan labu");
  await expect(row).toContainText("codziennie, 22:00–06:00");
  await expect(row).toContainText("pon–pt");
  await expect(row).toContainText("wznowienie");
  await page.getByPlaceholder("np. Nocny skan kampusu").fill("Weekend");
  await page.getByLabel("Cele harmonogramu").fill("10.20.0.0/18");
  await page.getByLabel("Częstotliwość").selectOption("10080");
  await page.getByLabel("Początek okna").fill("01:00");
  await page.getByLabel("Koniec okna").fill("05:00");
  await page.getByRole("button", { name: "Dodaj harmonogram" }).click();
  await expect
    .poll(() => sent.find((s) => s.method === "POST")?.body)
    .toMatchObject({
      name: "Weekend",
      text: "10.20.0.0/18",
      interval_minutes: 10080,
      window_start: "01:00",
      window_end: "05:00",
    });
});

test("skan jednorazowy: start i koniec o zadanej godzinie", async ({ page }) => {
  const sent = await stubApi(page);
  await page.goto("/admin/discovery/harmonogram");
  await page.getByLabel("jednorazowo: start i koniec o zadanej godzinie").check();
  await expect(page.getByLabel("Częstotliwość")).toHaveCount(0);
  await page.getByPlaceholder("np. Nocny skan kampusu").fill("Audyt sobota");
  await page.getByLabel("Cele harmonogramu").fill("10.20.0.0/18");
  await page.getByLabel("Start skanu").fill("2026-11-28T01:00");
  await page.getByLabel("Koniec skanu").fill("2026-11-28T05:00");
  await page.getByRole("button", { name: "Dodaj harmonogram" }).click();
  await expect
    .poll(() => {
      const body = sent.find((s) => s.method === "POST")?.body as Record<string, string>;
      return body && [body.name, Boolean(body.start_at), Boolean(body.end_at)];
    })
    .toEqual(["Audyt sobota", true, true]);
});

test("przebieg: raport HTML/JSON/CSV i panel wznowienia po końcu okna", async ({ page }) => {
  const sent = await stubApi(page);
  await page.route("**/api/discovery/runs/44444444-4444-4444-4444-444444444444", (route) =>
    route.fulfill({
      json: {
        ...JSON.parse(
          readFileSync(new URL("./fixtures/discovery_run.json", import.meta.url), "utf-8"),
        ),
        status: "paused",
        deadline: "2026-11-28T05:00:00Z",
        summary: { remaining_addresses: 8192 },
        remaining: { networks: 2, hosts: 5 },
        resumed_by: null,
      },
    }),
  );
  await page.route("**/api/discovery/runs/*/report?format=*", (route) =>
    route.fulfill({ body: "<html></html>", contentType: "text/html" }),
  );
  await page.goto("/admin/discovery/44444444-4444-4444-4444-444444444444");
  const paused = page.locator("[data-demo=run-paused]");
  await expect(paused).toContainText("8192 adresów (2 zakresów, 5 hostów bez skanu usług)");
  await expect(page.getByRole("button", { name: "Raport HTML" })).toBeVisible();
  await page.getByRole("button", { name: "Wznów" }).click();
  await expect.poll(() => sent.find((s) => s.path.endsWith("/resume"))?.method).toBe("POST");
});

test("porównanie: wykres zmian w czasie dla zakończonych przebiegów", async ({ page }) => {
  await stubApi(page);
  await page.goto("/admin/discovery/porownanie");
  const trend = page.locator("[data-demo=trend]");
  await expect(trend.getByRole("figure", { name: "Aktywne hosty" })).toBeVisible();
  await expect(trend.getByRole("figure", { name: "Usługi" }).getByRole("button")).toHaveCount(3);
  await trend.screenshot({ path: "test-results/trend.png" });
});

test("rola Odczyt widzi sygnatury, ale bez edytora", async ({ page }) => {
  await stubApi(page, { role: "viewer" });
  await page.goto("/admin/discovery/sygnatury");
  await expect(page.getByRole("cell", { name: "gitea", exact: true })).toBeVisible();
  await expect(page.getByLabel("Sygnatura w YAML")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Usuń" })).toHaveCount(0);
});

test("pulpit: wskaźniki na górze, bez zdublowanych kafelków; Sentek z szybkimi akcjami", async ({
  page,
}) => {
  await stubApi(page);
  await page.goto("/admin/");
  const kpis = page.getByRole("region", { name: "Kluczowe wskaźniki" });
  for (const label of [
    "Aktywne zagrożenia",
    "Katalog CISA KEV",
    "Zasoby w inwentarzu",
    "Wymaga decyzji / akcji",
  ]) {
    await expect(kpis.getByText(label, { exact: true })).toBeVisible();
  }
  await expect(page.getByText("Zmiany od ostatniego skanu")).toHaveCount(0);
  await expect(page.getByText("Ostatnie skany i zmiany")).toHaveCount(0);

  const sentek = page.getByRole("button", { name: "Zapytaj Sentka" });
  await sentek.hover();
  await expect(page.getByText(/Pytaj o skany/)).toBeVisible();
  await sentek.click();
  await page.getByRole("button", { name: "Podsumuj krytyczne zagrożenia" }).click();
  await expect(
    page.getByRole("region", { name: "Asystent Sentek" }).locator("p").nth(1),
  ).toBeVisible();
});

test("konsola czeka na API po restarcie (502) zamiast pokazywać błąd", async ({ page }) => {
  await stubApi(page);
  let calls = 0;
  await page.route("**/api/console/admin", (route) => {
    calls += 1;
    return route.fulfill({ status: calls <= 2 ? 502 : 204 });
  });
  await page.goto("/admin/");
  await expect(page.getByText("API jeszcze się uruchamia, czekam…")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Pulpit" })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText(/Błąd serwera \(502\)/)).toHaveCount(0);
});

test("IAM: ludzie i tożsamości nie-ludzkie osobno, delegacja warstwy na podsieć", async ({
  page,
}) => {
  const sent = await stubApi(page);
  await page.goto("/admin/");
  await nav(page).getByRole("button", { name: "Kontrola" }).click();
  await nav(page).getByRole("link", { name: "IAM: role i użytkownicy" }).click();
  await expect(page.getByRole("heading", { name: "IAM: role i użytkownicy" })).toBeVisible();
  await expect(page.getByRole("tab", { name: /Ludzie/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  const overview = page.getByTestId("layer-overview");
  for (const name of ["Warstwa 1: Skan deterministyczny", "Warstwa 2: Analiza LLM"]) {
    await expect(overview.getByText(name)).toBeVisible();
  }
  await expect(page.getByTestId("layers-analityk")).toContainText("warstwa 1 (10.20.0.0/28)");
  await expect(page.getByTestId("layers-admin")).toContainText("z roli Administracja");

  const form = page.getByRole("form", { name: "Nowa delegacja" });
  // Administratora nie da się delegować (ma warstwy z roli).
  await expect(form.getByLabel("Osoba").locator("option", { hasText: "(admin)" })).toHaveCount(0);
  await form.getByLabel("Osoba").selectOption({ label: "Anna Analityk (analityk)" });
  await form.getByLabel("Warstwa").selectOption("3");
  await form.getByLabel(/Jednostka \/ podsieć/).fill("10.20.0.0/28, 10.20.1.0/29");
  await form.getByLabel("Powód (do audytu)").fill("Przegląd serwerowni B");
  await form.getByRole("button", { name: "Deleguj" }).click();
  await expect(page.getByRole("status")).toContainText("Delegowano");
  const created = sent.find((s) => s.path === "/api/iam/delegations");
  expect(created?.body).toMatchObject({ layer: 3, scope: ["10.20.0.0/28", "10.20.1.0/29"] });

  await page.getByRole("button", { name: "Odwołaj delegację analityk warstwa 1" }).click();
  await expect.poll(() => sent.some((s) => s.path.endsWith("/revoke"))).toBe(true);

  await page.getByRole("tab", { name: /non-human/ }).click();
  await expect(page.getByText("Agent AI (warstwa 3)")).toBeVisible();
  await expect(page.getByText("aktywny, zdolności v2")).toBeVisible();
  await expect(page.getByRole("cell", { name: "sentinel-agent" })).toBeVisible();
  await expect(page.getByRole("form", { name: "Nowe zdolności agenta" })).toBeVisible();
});

test("trzy warstwy: osobne karty, grupy podatności, warstwa 2 i DefectDojo na żądanie", async ({
  page,
}) => {
  const sent = await stubApi(page);
  await page.goto("/admin/");
  await expect(page.getByRole("region", { name: "Warstwa 1: skan podatności" })).toContainText(
    "Anonimowe logowanie FTP",
  );
  await nav(page).getByRole("button", { name: "Kontrola" }).click();
  await nav(page).getByRole("link", { name: "Warstwy skanowania" }).click();
  for (const id of ["layer-1", "layer-2", "layer-3"]) {
    await expect(page.getByTestId(id)).toBeVisible();
  }
  // Wejście na stronę niczego nie uruchamia.
  expect(sent.filter((s) => s.path.startsWith("/api/redteam"))).toEqual([]);

  const form = page.getByRole("form", { name: "Uruchom warstwę 1" });
  await form.getByLabel("Cele (IP albo CIDR)").fill("10.20.0.0/28");
  await form.getByLabel(/Powód/).fill("Przegląd po zmianie konfiguracji");
  await form.getByRole("button", { name: "Uruchom warstwę 1" }).click();
  await expect(page.getByRole("heading", { name: "Przebieg warstwy 1" })).toBeVisible();
  expect(sent.map((s) => s.path)).toEqual(["/api/redteam/layer1/runs"]);

  await page.getByRole("button", { name: "Przestarzałe protokoły TLS" }).click();
  await expect(page.getByText("10.20.0.6:443/tcp")).toBeVisible();
  await expect(page.getByText("Ustaw minimalną wersję protokołu na TLS 1.2")).toBeVisible();
  await expect(page.getByTestId("analysis")).toContainText("szablon reguł (bez modelu)");

  await page.getByRole("button", { name: "Analizuj (warstwa 2)" }).click();
  await page.getByRole("button", { name: /Wyślij grupy do DefectDojo/ }).click();
  await expect(page.getByText("Wysłano 4 zgrupowanych findingów do DefectDojo.")).toBeVisible();
  expect(sent.map((s) => s.path).slice(1)).toEqual([
    `/api/redteam/runs/7c1e0d2a-3b4f-4c5d-8e9f-a0b1c2d3e4f5/analysis`,
    `/api/redteam/runs/7c1e0d2a-3b4f-4c5d-8e9f-a0b1c2d3e4f5/defectdojo`,
  ]);
});
