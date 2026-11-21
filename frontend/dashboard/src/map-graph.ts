/** Graf mapy organizacji (Cytoscape): działy jako ramki, urządzenia w środku, kolor = ryzyko. */
import type { ElementDefinition, StylesheetJson } from "cytoscape";

import type { Device, OrgUnitSummary, RiskLevel } from "@shared/lib/api";

export const RISK_COLORS: Record<RiskLevel | "brak", string> = {
  krytyczny: "#c62828",
  wysoki: "#eb6834",
  średni: "#c99400",
  niski: "#1baf7a",
  brak: "#94a3b8",
};

export const NO_UNIT = "unit:none";

const COLS = 4;
const STEP_X = 96;
const STEP_Y = 66;
const HEADER = 46;
const COLUMN_GAP = 90;

/**
 * Działy najwyższego poziomu to kolumny; w kolumnie najpierw urządzenia działu (siatka po
 * 4), pod nimi poddziały. Układ jest stały (preset), więc mapa wygląda tak samo przy każdym
 * odświeżeniu i w nagraniu demo.
 */
export function buildElements(units: OrgUnitSummary[], devices: Device[]): ElementDefinition[] {
  const known = new Set(units.map((u) => u.id));
  const byUnit = new Map<string, Device[]>();
  for (const d of devices) {
    const key = d.unit_id && known.has(d.unit_id) ? d.unit_id : NO_UNIT;
    byUnit.set(key, [...(byUnit.get(key) ?? []), d]);
  }
  const children = (id: string | null) =>
    units.filter((u) => u.parent_id === id).sort((a, b) => a.name.localeCompare(b.name, "pl"));
  const hasDevices = (id: string): boolean =>
    (byUnit.get(id)?.length ?? 0) > 0 || children(id).some((c) => hasDevices(c.id));

  const elements: ElementDefinition[] = [];
  const placeDevices = (list: Device[], parent: string, x: number, y: number): number => {
    list
      .slice()
      .sort((a, b) => b.max_score - a.max_score || a.name.localeCompare(b.name))
      .forEach((d, index) => {
        const level = d.worst_level ?? "brak";
        elements.push({
          data: {
            id: d.id,
            label: d.name,
            parent,
            color: RISK_COLORS[level],
            size: 22 + Math.min(d.open_findings, 5) * 5,
            level,
          },
          position: { x: x + (index % COLS) * STEP_X, y: y + Math.floor(index / COLS) * STEP_Y },
          classes: [
            "device",
            d.status === "shadow" ? "shadow" : "",
            d.exposure === "internet" ? "internet" : "",
          ]
            .filter(Boolean)
            .join(" "),
        });
      });
    return Math.ceil(list.length / COLS) * STEP_Y;
  };
  // Zwraca wysokość zajętą przez dział razem z poddziałami.
  const placeUnit = (unit: OrgUnitSummary, parent: string | undefined, x: number, y: number) => {
    const id = `unit:${unit.id}`;
    elements.push({ data: { id, label: unit.name, parent }, classes: "unit" });
    let height = placeDevices(byUnit.get(unit.id) ?? [], id, x, y + HEADER);
    for (const child of children(unit.id).filter((c) => hasDevices(c.id))) {
      height += placeUnit(child, id, x + 12, y + HEADER + height) + 24;
    }
    return HEADER + height;
  };

  let x = 0;
  for (const root of children(null).filter((u) => hasDevices(u.id))) {
    placeUnit(root, undefined, x, 0);
    x += COLS * STEP_X + COLUMN_GAP;
  }
  const loose = byUnit.get(NO_UNIT) ?? [];
  if (loose.length) {
    elements.push({ data: { id: NO_UNIT, label: "Bez działu" }, classes: "unit unassigned" });
    placeDevices(loose, NO_UNIT, x, HEADER);
  }
  return elements;
}

export const MAP_STYLE: StylesheetJson = [
  {
    selector: "node.unit",
    style: {
      label: "data(label)",
      "text-valign": "top",
      "text-halign": "center",
      "font-size": 13,
      "font-weight": 600,
      color: "#1e293b",
      "background-color": "#f1f5f9",
      "background-opacity": 0.7,
      "border-color": "#cbd5e1",
      "border-width": 1.5,
      shape: "round-rectangle",
      padding: "18px",
    },
  },
  {
    selector: "node.unassigned",
    style: { "border-style": "dashed", "border-color": "#c99400", "background-color": "#fffbeb" },
  },
  {
    selector: "node.device",
    style: {
      label: "data(label)",
      "font-size": 10,
      color: "#334155",
      "text-valign": "bottom",
      "text-margin-y": 4,
      "background-color": "data(color)",
      width: "data(size)",
      height: "data(size)",
      "border-color": "#ffffff",
      "border-width": 2,
    },
  },
  { selector: "node.device.internet", style: { shape: "diamond" } },
  {
    selector: "node.device.shadow",
    style: { "border-color": "#c99400", "border-width": 3, "border-style": "dashed" },
  },
  {
    selector: "node.device:selected, node.device.highlight",
    style: { "border-color": "#0f172a", "border-width": 4 },
  },
  { selector: "node.faded", style: { opacity: 0.2 } },
];
