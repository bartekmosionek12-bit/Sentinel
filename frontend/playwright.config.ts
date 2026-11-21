/**
 * Testy interfejsu konsoli (Playwright). API jest podstawione danymi z e2e/fixtures
 * (fikcyjna organizacja z demo-lab), więc testy sprawdzają interfejs: samouczek, Sentka,
 * mapę i kolejkę próśb admina. Zachowanie API sprawdza pytest, a całą ścieżkę na żywo
 * job e2e-demo w CI (scripts/check_demo.py).
 */
import { defineConfig } from "@playwright/test";

const browser = process.env.PLAYWRIGHT_CHROMIUM ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM } : {};

export default defineConfig({
  testDir: "e2e",
  timeout: 30_000,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    viewport: { width: 1440, height: 900 },
    trace: "off",
    launchOptions: browser,
  },
  webServer: [
    {
      command: "npx vite --config dashboard/vite.config.ts --port 5174 --strictPort",
      url: "http://localhost:5174/dashboard/",
      reuseExistingServer: !process.env.CI,
    },
    {
      command: "npx vite --config admin/vite.config.ts --port 5173 --strictPort",
      url: "http://localhost:5173/admin/",
      reuseExistingServer: !process.env.CI,
    },
  ],
});
