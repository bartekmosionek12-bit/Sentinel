/**
 * Trend pokrycia inwentarza (§8.6): trzy odsetki na jednej osi 0–100%.
 * Kolory: sloty 1–3 zwalidowanej palety kategorycznej (niebieski, pomarańczowy, morski),
 * w stałej kolejności. Morski ma kontrast < 3:1 z tłem, więc każda seria ma etykietę na końcu
 * linii, legendę i widok tabeli; tożsamość nigdy nie zależy od samego koloru.
 */
import { useState } from "react";
import {
  CartesianGrid,
  LabelList,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { Table, Td, Th } from "@shared/components/ui/table";
import type { Coverage } from "@shared/lib/api";
import { formatDate } from "@shared/lib/utils";

const SERIES = [
  { key: "with_owner_pct", label: "właściciel", color: "#2a78d6" },
  { key: "scanned_recently_pct", label: "skan w 7 dni", color: "#eb6834" },
  { key: "known_version_pct", label: "znana wersja", color: "#1baf7a" },
] as const;

const pct = (value: number) => `${value.toFixed(0)}%`;

export function CoverageTrend({ trend }: { trend: Coverage[] }) {
  const [table, setTable] = useState(false);
  if (trend.length < 2) {
    return (
      <p className="text-sm text-muted-foreground">
        Wykres trendu pojawi się po drugim dziennym pomiarze. Pomiar wykonuje się raz na dobę.
      </p>
    );
  }
  const data = trend.map((row) => ({ ...row, label: formatDate(row.day) }));
  const last = data.length - 1;
  return (
    <div>
      <ul className="mb-2 flex flex-wrap gap-4 text-xs text-muted-foreground" aria-label="Legenda">
        {SERIES.map((s) => (
          <li key={s.key} className="flex items-center gap-1.5">
            <span className="inline-block h-0.5 w-4 rounded" style={{ background: s.color }} />
            {s.label}
          </li>
        ))}
      </ul>
      {table ? (
        <Table>
          <thead>
            <tr>
              <Th>Dzień</Th>
              {SERIES.map((s) => (
                <Th key={s.key}>{s.label}</Th>
              ))}
              <Th>nieznane</Th>
            </tr>
          </thead>
          <tbody>
            {data.map((row) => (
              <tr key={row.day}>
                <Td>{row.label}</Td>
                {SERIES.map((s) => (
                  <Td key={s.key} className="tabular-nums">
                    {pct(row[s.key])}
                  </Td>
                ))}
                <Td className="tabular-nums">{row.unknown_devices}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : (
        <div className="h-56" role="img" aria-label="Trend pokrycia inwentarza w procentach">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 8, right: 130, bottom: 0, left: 0 }}>
              <CartesianGrid stroke="#e7e5e4" vertical={false} />
              <XAxis
                dataKey="label"
                tick={{ fontSize: 11, fill: "#6b6b66" }}
                tickLine={false}
                axisLine={{ stroke: "#d6d3d1" }}
              />
              <YAxis
                domain={[0, 100]}
                ticks={[0, 25, 50, 75, 100]}
                tickFormatter={pct}
                tick={{ fontSize: 11, fill: "#6b6b66" }}
                tickLine={false}
                axisLine={false}
                width={40}
              />
              <Tooltip
                formatter={(value, name) => [pct(Number(value)), String(name)]}
                cursor={{ stroke: "#a8a29e", strokeWidth: 1 }}
              />
              {SERIES.map((s) => (
                <Line
                  key={s.key}
                  dataKey={s.key}
                  name={s.label}
                  stroke={s.color}
                  strokeWidth={2}
                  dot={{ r: 4, strokeWidth: 2, stroke: "#ffffff", fill: s.color }}
                  activeDot={{ r: 5, strokeWidth: 2, stroke: "#ffffff" }}
                  isAnimationActive={false}
                >
                  <LabelList
                    dataKey={s.key}
                    content={({ x, y, value, index }) =>
                      index === last ? (
                        <text x={Number(x) + 8} y={Number(y) + 4} fontSize={11} fill="#3f3f3a">
                          {`${pct(Number(value))} ${s.label}`}
                        </text>
                      ) : null
                    }
                  />
                </Line>
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
      <button
        type="button"
        className="mt-2 text-xs text-muted-foreground underline"
        onClick={() => setTable(!table)}
      >
        {table ? "Pokaż wykres" : "Pokaż jako tabelę"}
      </button>
    </div>
  );
}
