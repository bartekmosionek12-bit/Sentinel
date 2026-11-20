// Przypadki promptfoo z fixtures/*.yaml, z asercjami wyłącznie deterministycznymi (bez LLM jako
// oceniającego). Każdy zestaw (mock, qwen, full) dostaje te same asercje bezpieczeństwa.
const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");

const ASSERTIONS = "file://assertions.js";

function load() {
  const dir = path.join(__dirname, "fixtures");
  return fs
    .readdirSync(dir)
    .filter((name) => name.endsWith(".yaml"))
    .sort()
    .flatMap((name) => yaml.load(fs.readFileSync(path.join(dir, name), "utf8")).cases);
}

function toTest(item, { mock }) {
  const assert = [
    { type: "javascript", value: `${ASSERTIONS}:assessmentUnchanged`, metric: "ocena_bez_zmian" },
    { type: "javascript", value: `${ASSERTIONS}:nothingForbiddenShown`, metric: "brak_wstrzyknietej_tresci" },
    { type: "javascript", value: `${ASSERTIONS}:noAddressOrLink`, metric: "brak_adresow_i_linkow" },
  ];
  if (mock && item.trigger) {
    // Bez tego przypadek byłby pusty: atrapa musi zobaczyć wstrzyknięcie w prompcie.
    assert.push({ type: "javascript", value: `${ASSERTIONS}:injectionReachedModel`, metric: "atak_dotarl_do_modelu" });
  }
  if (mock && item.expect_passed_with_mock) {
    assert.push({ type: "javascript", value: `${ASSERTIONS}:honestAnswerAccepted`, metric: "kontrola_przepuszcza" });
  }
  return {
    description: `${item.id}: ${item.title}`,
    vars: {
      case: item.id,
      // Tekst JSON: tablica w vars oznaczałaby w promptfoo osobny test dla każdego elementu.
      forbidden: JSON.stringify(item.forbidden || []),
      pipeline: item.pipeline || "report",
    },
    assert,
  };
}

module.exports = {
  mock: () => load().map((item) => toTest(item, { mock: true })),
  qwen: () => load().filter((item) => item.qwen).map((item) => toTest(item, { mock: false })),
  full: () => load().map((item) => toTest(item, { mock: false })),
};
