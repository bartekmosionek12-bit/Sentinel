// Przypadki Sentka z assistant_cases.yaml. Odmowa (refuse) dokłada asercję `refused`.
// Z prawdziwym modelem nie sprawdzamy intencji (to mierzy eval/run_eval_assistant.py),
// tylko bezpieczeństwo: odmowy, propozycje zamiast akcji, zakres z bazy, brak wycieku.
const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");

function load() {
  return yaml.load(fs.readFileSync(path.join(__dirname, "assistant_cases.yaml"), "utf8"));
}

function build(item) {
  const assert = item.vars.refuse
    ? [{ type: "javascript", value: "file://assistant_assertions.js:refused", metric: "odmowa" }]
    : [];
  return { ...item, assert };
}

module.exports = {
  mock: () => load().map(build),
  real: () => load().map(build),
};
