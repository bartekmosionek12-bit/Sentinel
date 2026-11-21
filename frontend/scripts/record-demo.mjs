/**
 * Nagrywarka filmu demo (moduł 22). Uruchamia ją scripts/record_demo.sh (przez make_demo.sh).
 *
 * Każda scena z demo/script.yaml to osobny klip 1920×1080 nagrany Playwrightem na prawdziwym
 * API (bez atrap). Moment startu sceny trafia do clips.json, a scripts/assemble_demo.sh tnie
 * klip dokładnie od tego miejsca. Logowanie idzie przez prawdziwy Keycloak (hasło + TOTP),
 * do DefectDojo zwykłym formularzem logowania.
 *
 * Zmienne: BASE_URL, SCRIPT_JSON, STAGE_JSON, OUT_DIR, CREDENTIALS, DD_URL, DD_USER,
 * DD_PASSWORD, CHROMIUM (opcjonalnie), ONLY (id sceny).
 */
import { createHmac } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";

import { chromium } from "@playwright/test";

const ROOT = path.resolve(import.meta.dirname, "..", "..");
const BASE = process.env.BASE_URL ?? "http://localhost:8080";
const DD_URL = process.env.DD_URL ?? "http://localhost:8081";
const SCRIPT = JSON.parse(readFileSync(process.env.SCRIPT_JSON, "utf8"));
const STAGE = JSON.parse(readFileSync(process.env.STAGE_JSON, "utf8"));
const OUT = process.env.OUT_DIR ?? path.join(ROOT, "demo", "out", "clips");
const [WIDTH, HEIGHT] = SCRIPT.resolution;

function credentials() {
  const file = process.env.CREDENTIALS ?? path.join(ROOT, "data", "demo-credentials.env");
  return Object.fromEntries(
    readFileSync(file, "utf8")
      .split("\n")
      .filter((line) => line.includes("=") && !line.startsWith("#"))
      .map((line) => [line.slice(0, line.indexOf("=")).trim(), line.slice(line.indexOf("=") + 1).trim()]),
  );
}

/** TOTP jak w scripts/oidc_login.py: bajty sekretu w postaci, w jakiej zapisał go Keycloak. */
function totp(secret, at = Date.now() / 1000) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30)));
  const digest = createHmac("sha1", Buffer.from(secret, "utf8")).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const code = (digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(code).padStart(6, "0");
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const fill = (text) => text.replace(/\{(run\d|import)\}/g, (_, key) => STAGE[key]);

/** Logowanie w Keycloaku i w DefectDojo; zwraca połączony stan sesji dla klipów. */
async function login(browser, username, password, secret) {
  const context = await browser.newContext({ viewport: { width: WIDTH, height: HEIGHT } });
  const page = await context.newPage();
  await page.goto(`${BASE}/admin/`);
  await page.locator("#username").fill(username);
  await page.locator("#password").fill(password);
  await page.locator("#kc-login").click();
  if (secret) {
    await page.locator("#otp").waitFor({ timeout: 15_000 });
    // Kod TOTP wolno użyć raz: czekamy na świeże okno 30 s, gdy obecne zaraz się kończy.
    if (Date.now() / 1000 % 30 > 25) await sleep(6000);
    await page.locator("#otp").fill(totp(secret));
    await page.locator("#kc-login").click();
  }
  await page.waitForURL(`${BASE}/admin/**`, { timeout: 20_000 });
  if (process.env.DD_PASSWORD) {
    await page.goto(`${DD_URL}/login`);
    await page.locator("#id_username").fill(process.env.DD_USER ?? "admin");
    await page.locator("#id_password").fill(process.env.DD_PASSWORD);
    await page.locator("form button[type=submit], form input[type=submit]").first().click();
    await page.waitForURL((url) => !url.pathname.startsWith("/login"), { timeout: 20_000 });
  }
  const state = await context.storageState();
  await context.close();
  return state;
}

async function ready(page) {
  await page.waitForFunction(() => Boolean(window.sentinelDemo), null, { timeout: 30_000 });
}

/** Wykonanie jednego kroku sceny. Brak elementu przerywa nagranie (scena musi być prawdziwa). */
async function perform(page, step, base) {
  const target = step.sel ? page.locator(step.sel).first() : null;
  switch (step.do) {
    case "highlight":
      await target.waitFor({ timeout: 15_000 });
      if (!(await page.evaluate((s) => window.sentinelDemo.scene(s), { ...base, highlight: step.sel })))
        throw new Error(`brak elementu ${step.sel}`);
      return;
    case "click":
      await target.click({ timeout: 15_000 });
      return;
    case "fill":
      await target.fill(step.text, { timeout: 15_000 });
      return;
    case "upload":
      await page.locator(step.sel).first().setInputFiles(path.join(ROOT, step.file));
      return;
    case "check": {
      const boxes = page.locator(step.sel);
      await boxes.first().waitFor({ timeout: 15_000 });
      const count = Math.min(step.count ?? 1, await boxes.count());
      for (let i = 0; i < count; i += 1) await boxes.nth(i).check();
      return;
    }
    case "goto":
      // Nawigacja w aplikacji (bez przeładowania strony i ponownego logowania).
      await page.evaluate((to) => {
        window.history.pushState({}, "", `/admin${to}`);
        window.dispatchEvent(new PopStateEvent("popstate"));
      }, fill(step.path));
      await page.evaluate((s) => window.sentinelDemo.scene(s), base);
      return;
    case "defectdojo":
      await page.goto(`${DD_URL}${step.path}`);
      return;
    default:
      throw new Error(`nieznana akcja ${step.do}`);
  }
}

async function recordScene(browser, scene, state) {
  const dir = path.join(OUT, "raw");
  mkdirSync(dir, { recursive: true });
  const context = await browser.newContext({
    storageState: state,
    viewport: { width: WIDTH, height: HEIGHT },
    recordVideo: { dir, size: { width: WIDTH, height: HEIGHT } },
  });
  const page = await context.newPage();
  const opened = Date.now();
  await page.goto(`${BASE}/admin${fill(scene.path)}${scene.path.includes("?") ? "&" : "?"}demo=record`);
  await ready(page);
  await page.waitForLoadState("networkidle").catch(() => undefined);
  await sleep(500);
  const base = { pose: scene.pose, side: scene.side, bubble: scene.bubble };
  await page.evaluate((s) => window.sentinelDemo.scene(s), base);
  // Początek sceny w klipie: od tego miejsca tnie assemble_demo.sh.
  const offset = Date.now() - opened;
  const elapsed = () => Date.now() - opened - offset;
  for (const step of scene.steps ?? []) {
    await sleep(Math.max(0, step.at * 1000 - elapsed()));
    try {
      await perform(page, step, base);
    } catch (error) {
      throw new Error(`Scena ${scene.id}, krok ${step.do} (${step.sel ?? step.path ?? ""}): ${error.message}`);
    }
  }
  if (scene.end_card) {
    await sleep(Math.max(0, scene.end_card_at * 1000 - elapsed()));
    await page.evaluate((s) => window.sentinelDemo.scene(s), { ...base, endCard: scene.end_card });
  }
  const duration = (scene.end - scene.start) * 1000;
  await sleep(Math.max(0, duration - elapsed()) + 300);
  const video = page.video();
  await context.close();
  const file = path.join(OUT, `${scene.id}.webm`);
  renameSync(await video.path(), file);
  return { id: scene.id, file, offset_ms: offset, duration_s: scene.end - scene.start };
}

async function main() {
  const creds = credentials();
  const browser = await chromium.launch(
    process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {},
  );
  const state = await login(browser, "admin", creds.DEMO_ADMIN_PASSWORD, creds.DEMO_ADMIN_TOTP_SECRET);
  const clips = [];
  for (const scene of SCRIPT.scenes) {
    if (process.env.ONLY && process.env.ONLY !== scene.id) continue;
    console.log(`Scena ${scene.id} (${scene.start}–${scene.end} s)`);
    clips.push(await recordScene(browser, scene, state));
  }
  await browser.close();
  writeFileSync(path.join(OUT, "clips.json"), JSON.stringify(clips, null, 2));
  console.log(`Klipy: ${OUT}`);
}

await main();
