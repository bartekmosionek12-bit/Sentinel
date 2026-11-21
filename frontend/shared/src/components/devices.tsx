/** Tabela urządzeń organizacji (Etap 6, #6/#18): sortowanie, filtry, eksport CSV, karta. */
import { useQuery } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, Download, EyeOff } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { QueryState } from "@shared/components/page";
import { RiskBadge } from "@shared/components/risk";
import { Badge } from "@shared/components/ui/badge";
import { Button } from "@shared/components/ui/button";
import { Input } from "@shared/components/ui/input";
import { Table, Td, Th } from "@shared/components/ui/table";
import { api, type Device, type DeviceFilter } from "@shared/lib/api";
import { people } from "@shared/lib/devices";
import { DEVICE_STATUS_LABELS, DEVICE_TYPE_LABELS } from "@shared/lib/labels";
import { setPseudonyms, usePseudonyms } from "@shared/lib/privacy";
import { formatDate } from "@shared/lib/utils";

type SortKey = "risk" | "name" | "unit" | "type" | "findings" | "status";

const SORTS: Record<SortKey, (d: Device) => string | number> = {
  risk: (d) => d.max_score,
  name: (d) => d.name.toLowerCase(),
  unit: (d) => (d.unit ?? "~").toLowerCase(),
  type: (d) => DEVICE_TYPE_LABELS[d.type] ?? d.type,
  findings: (d) => d.open_findings,
  status: (d) => d.status,
};

export function PseudonymToggle() {
  const on = usePseudonyms();
  return (
    <label className="flex cursor-pointer items-center gap-2 text-sm text-muted-foreground">
      <input
        type="checkbox"
        checked={on}
        onChange={(event) => setPseudonyms(event.target.checked)}
        className="size-4"
      />
      <EyeOff className="size-4" aria-hidden />
      Pokaż pseudonimy zamiast nazwisk
    </label>
  );
}

export function DeviceStatus({ device }: { device: Device }) {
  if (device.status === "shadow")
    return (
      <Badge variant="warn" title="Widziane w sieci, nie ma go w CMDB, AD ani MDM">
        Nieznane
      </Badge>
    );
  if (device.status === "missing") return <Badge variant="neutral">Nie odpowiada</Badge>;
  return <Badge variant="ok">{DEVICE_STATUS_LABELS[device.status] ?? device.status}</Badge>;
}

/** Komórka CSV bez wstrzyknięcia formuł (=, +, -, @ na początku) i z cudzysłowami. */
function cell(value: string | number): string {
  let text = String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

/** Eksport zawsze z pseudonimami (§15), niezależnie od przełącznika i uprawnień. */
async function exportCsv(filter: DeviceFilter, name: string): Promise<void> {
  const data = await api.devices({ ...filter, pseudonyms: true });
  const header = [
    "Urządzenie",
    "Typ",
    "Stan",
    "Dział",
    "Lokalizacja",
    "Właściciel",
    "Użytkownik",
    "Otwarte zagrożenia",
    "Najwyższe ryzyko",
    "Źródła",
    "Ostatni skan",
  ];
  const rows = data.items.map((d) => [
    d.name,
    DEVICE_TYPE_LABELS[d.type] ?? d.type,
    DEVICE_STATUS_LABELS[d.status] ?? d.status,
    d.unit ?? "",
    d.location ?? "",
    people(d.owners),
    people(d.users),
    d.open_findings,
    d.worst_level ? `${d.worst_level} (${d.max_score.toFixed(1)})` : "",
    d.sources.join("; "),
    d.last_scan ? formatDate(d.last_scan) : "",
  ]);
  const csv = [header, ...rows].map((r) => r.map(cell).join(";")).join("\r\n");
  const url = URL.createObjectURL(new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function DeviceTable({
  filter = {},
  basePath,
  csvName = "urzadzenia.csv",
  showUnitFilter = true,
  emptyText = "Brak urządzeń.",
}: {
  filter?: DeviceFilter;
  basePath: string;
  csvName?: string;
  showUnitFilter?: boolean;
  emptyText?: string;
}) {
  const pseudonyms = usePseudonyms();
  const [search, setSearch] = useState("");
  const [unit, setUnit] = useState<string>("");
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: "risk", desc: true });
  const devices = useQuery({
    queryKey: ["devices", filter, pseudonyms],
    queryFn: () => api.devices({ ...filter, pseudonyms }),
    refetchInterval: 5_000,
  });
  const units = useMemo(
    () => [...new Set((devices.data?.items ?? []).map((d) => d.unit).filter(Boolean))].sort(),
    [devices.data],
  ) as string[];
  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const get = SORTS[sort.key];
    return (devices.data?.items ?? [])
      .filter((d) => !unit || d.unit === unit)
      .filter(
        (d) =>
          !needle ||
          [d.name, d.unit, d.location, people(d.owners), people(d.users)]
            .join(" ")
            .toLowerCase()
            .includes(needle),
      )
      .sort((a, b) => {
        const x = get(a);
        const y = get(b);
        const order = x < y ? -1 : x > y ? 1 : 0;
        return sort.desc ? -order : order;
      });
  }, [devices.data, search, unit, sort]);

  const header = (key: SortKey, label: string) => {
    const active = sort.key === key;
    const Icon = sort.desc ? ArrowDown : ArrowUp;
    return (
      <Th aria-sort={active ? (sort.desc ? "descending" : "ascending") : "none"}>
        <button
          type="button"
          className="inline-flex items-center gap-1 uppercase hover:text-foreground"
          onClick={() =>
            setSort({ key, desc: active ? !sort.desc : key === "risk" || key === "findings" })
          }
        >
          {label}
          {active && <Icon className="size-3" aria-hidden />}
        </button>
      </Th>
    );
  };

  return (
    <div data-demo="device-table">
      <div className="flex flex-wrap items-center gap-3 border-b border-border p-3">
        <Input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Szukaj: urządzenie, dział, osoba"
          aria-label="Szukaj urządzeń"
          className="max-w-xs"
        />
        {showUnitFilter && (
          <select
            value={unit}
            onChange={(event) => setUnit(event.target.value)}
            aria-label="Dział"
            className="h-9 rounded-md border border-border bg-card px-2 text-sm"
          >
            <option value="">Wszystkie działy</option>
            {units.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        )}
        <span className="text-sm text-muted-foreground tabular-nums">
          {rows.length} z {devices.data?.total ?? 0}
        </span>
        <div className="ml-auto flex flex-wrap items-center gap-4">
          <PseudonymToggle />
          <Button
            variant="outline"
            size="sm"
            onClick={() => void exportCsv(filter, csvName)}
            title="Eksport zawsze z pseudonimami zamiast nazwisk"
          >
            <Download className="size-4" aria-hidden /> Eksport CSV
          </Button>
        </div>
      </div>
      <QueryState
        isPending={devices.isPending}
        error={devices.error}
        empty={rows.length === 0}
        emptyText={emptyText}
      />
      {rows.length > 0 && (
        <Table>
          <thead>
            <tr>
              {header("risk", "Ryzyko")}
              {header("name", "Urządzenie")}
              {header("type", "Typ")}
              {header("unit", "Dział")}
              <Th>Właściciel / użytkownik</Th>
              {header("findings", "Zagrożenia")}
              {header("status", "Stan")}
            </tr>
          </thead>
          <tbody>
            {rows.map((d) => (
              <tr key={d.id} className="hover:bg-muted/50">
                <Td>
                  {d.worst_level ? (
                    <RiskBadge level={d.worst_level} score={d.max_score} />
                  ) : (
                    <span className="text-xs text-muted-foreground">brak</span>
                  )}
                </Td>
                <Td>
                  <Link className="font-medium underline-offset-2 hover:underline" to={`${basePath}/${d.id}`}>
                    {d.name}
                  </Link>
                  {d.location && (
                    <span className="block text-xs text-muted-foreground">{d.location}</span>
                  )}
                </Td>
                <Td>{DEVICE_TYPE_LABELS[d.type] ?? d.type}</Td>
                <Td>{d.unit ?? <span className="text-muted-foreground">nieprzypisane</span>}</Td>
                <Td>
                  {people(d.owners) || people(d.users) || (
                    <span className="text-muted-foreground">brak</span>
                  )}
                  {d.owners.length > 0 && d.users.length > 0 && (
                    <span className="block text-xs text-muted-foreground">
                      używa: {people(d.users)}
                    </span>
                  )}
                </Td>
                <Td className="tabular-nums">{d.open_findings}</Td>
                <Td>
                  <DeviceStatus device={d} />
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}
