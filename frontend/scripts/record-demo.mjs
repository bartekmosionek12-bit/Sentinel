/**
 * Nagrywarka filmu demo (moduł 22). Uruchamia ją scripts/record_demo.sh.
 *
 * Każda scena z demo/script.yaml to osobny klip 1920×1080 (nagranie Playwright). Klip
 * zaczyna się od logowania i wczytania strony; moment startu sceny trafia do clips.json,
 * a scripts/assemble_demo.sh tnie klip dokładnie od tego miejsca. Logowanie idzie przez
 * prawdziwy Keycloak (hasło, a dla admina także TOTP), bez obejść.
 *
 * Zmienne: BASE_URL, SCRIPT_JSON, OUT_DIR, CREDENTIALS, CHROMIUM (opcjonalnie), ONLY (id sceny).
 */
import { execFileSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";

import { chromium } from "@playwright/test";

const ROOT = path.resolve(import.meta.dirname, "..", "..");
const BASE = process.env.BASE_URL ?? "http://localhost:8080";
const SCRIPT = JSON.parse(readFileSync(process.env.SCRIPT_JSON, "utf8"));
const OUT = process.env.OUT_DIR ?? path.join(ROOT, "demo", "out", "clips");
const [WIDTH, HEIGHT] = SCRIPT.resolution;

function credentials() {
  const file =
    process.env.CREDENTIALS ?? path.join(ROOT, "data", "demo-credentials.env");
  return Object.fromEntries(
    readFileSync(file, "utf8")
      .split("\n")
      .filter((line) => line.includes("=") && !line.startsWith("#"))
      .map((line) => [
        line.slice(0, line.indexOf("=")).trim(),
        line.slice(line.indexOf("=") + 1).trim(),
      ]),
  );
}

/** TOTP jak w scripts/oidc_login.py: bajty sekretu w postaci, w jakiej zapisał go Keycloak. */
function totp(secret, at = Date.now() / 1000) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30)));
  const digest = createHmac("sha1", Buffer.from(secret, "utf8"))
    .update(counter)
    .digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const code = (digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(code).padStart(6, "0");
}

/** Logowanie w Keycloaku; zwraca ciasteczka sesji SSO dla kontekstów z nagraniem. */
async function login(browser, app, username, password, secret) {
  const context = await browser.newContext({
    viewport: { width: WIDTH, height: HEIGHT },
  });
  const page = await context.newPage();
  await page.goto(`${BASE}/${app}/`);
  await page.locator("#username").fill(username);
  await page.locator("#password").fill(password);
  await page.locator("#kc-login").click();
  if (secret) {
    await page.locator("#otp").waitFor({ timeout: 15_000 });
    await page.locator("#otp").fill(totp(secret));
    await page.locator("#kc-login").click();
  }
  await page.waitForURL(`${BASE}/${app}/**`, { timeout: 20_000 });
  const state = await context.storageState();
  await context.close();
  return state;
}

// Akcje dozwolone w scenariuszu (lista w scripts/demo_script.py:ACTIONS).
const ACTIONS = {
  inject_kev: async () => {
    execFileSync(path.join(ROOT, "scripts", "inject_kev.sh"), {
      cwd: ROOT,
      stdio: "inherit",
    });
  },
  open_latest_report: async (page) => {
    await page.locator('[data-demo="inbox"] a').first().click();
  },
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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
  await page.goto(`${BASE}/${scene.app}${scene.path}?demo=record`);
  await page.waitForFunction(() => Boolean(window.sentinelDemo), null, {
    timeout: 30_000,
  });
  const preActions = (scene.actions ?? []).filter((a) => a !== "inject_kev");
  for (const name of preActions) await ACTIONS[name](page);
  if (scene.highlight && !(scene.actions ?? []).includes("inject_kev")) {
    await page.locator(scene.highlight).first().waitFor({ timeout: 15_000 });
  }
  await sleep(400);
  const show = (fields) =>
    page.evaluate((s) => window.sentinelDemo.scene(s), fields);
  const base = {
    pose: scene.pose,
    side: scene.side,
    bubble: scene.bubble,
    endCard: scene.end_card,
  };
  const duration = (scene.end - scene.start) * 1000;
  // Początek sceny w klipie: od tego miejsca tnie assemble_demo.sh.
  const offset = Date.now() - opened;
  if ((scene.actions ?? []).includes("inject_kev")) {
    // Zero-day na żywo: najpierw sama scena, potem wpis KEV i baner, gdy faktycznie przyjdzie.
    await show({ ...base, highlight: undefined });
    await ACTIONS.inject_kev(page);
    await page.locator(scene.highlight).first().waitFor({ timeout: 15_000 });
    const after = Date.now() - opened - offset;
    console.log(`  baner zero-day po ${after} ms od startu sceny`);
  }
  if (!(await show({ ...base, highlight: scene.highlight }))) {
    throw new Error(`Scena ${scene.id}: brak elementu ${scene.highlight}`);
  }
  if (scene.then) {
    await sleep(
      Math.max(0, scene.then.at * 1000 - (Date.now() - opened - offset)),
    );
    await show({
      ...base,
      highlight: scene.then.highlight,
      bubble: scene.then.bubble ?? scene.bubble,
    });
  }
  await sleep(Math.max(0, duration - (Date.now() - opened - offset)) + 300);
  const video = page.video();
  await context.close();
  const file = path.join(OUT, `${scene.id}.webm`);
  renameSync(await video.path(), file);
  return {
    id: scene.id,
    file,
    offset_ms: offset,
    duration_s: scene.end - scene.start,
  };
}

async function main() {
  const creds = credentials();
  const browser = await chromium.launch(
    process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {},
  );
  const states = {
    dashboard: await login(
      browser,
      "dashboard",
      "manager",
      creds.DEMO_MANAGER_PASSWORD,
    ),
    admin: await login(
      browser,
      "admin",
      "admin",
      creds.DEMO_ADMIN_PASSWORD,
      creds.DEMO_ADMIN_TOTP_SECRET,
    ),
  };
  const clips = [];
  for (const scene of SCRIPT.scenes) {
    if (process.env.ONLY && process.env.ONLY !== scene.id) continue;
    console.log(`Scena ${scene.id} (${scene.start}–${scene.end} s)`);
    clips.push(await recordScene(browser, scene, states[scene.app]));
  }
  await browser.close();
  writeFileSync(path.join(OUT, "clips.json"), JSON.stringify(clips, null, 2));
  console.log(`Klipy: ${OUT}`);
}

await main();
