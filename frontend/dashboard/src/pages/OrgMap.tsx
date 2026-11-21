/** Mapa organizacji (#6): działy i urządzenia na jednym obrazie; kliknięcie otwiera kartę. */
import { useQuery } from "@tanstack/react-query";
import cytoscape, { type Core } from "cytoscape";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { buildElements, MAP_STYLE, RISK_COLORS } from "@/map-graph";
import { PageHeader, QueryState } from "@shared/components/page";
import { Card, CardContent } from "@shared/components/ui/card";
import { api } from "@shared/lib/api";
import { usePseudonyms } from "@shared/lib/privacy";

const LEGEND: [string, string][] = [
  ["Krytyczne", RISK_COLORS.krytyczny],
  ["Wysokie", RISK_COLORS.wysoki],
  ["Średnie", RISK_COLORS.średni],
  ["Niskie", RISK_COLORS.niski],
  ["Bez zagrożeń", RISK_COLORS.brak],
];

export function OrgMap() {
  const navigate = useNavigate();
  const pseudonyms = usePseudonyms();
  const [location, setLocation] = useState("");
  const [onlyRisky, setOnlyRisky] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const graph = useRef<Core | null>(null);
  const overview = useQuery({ queryKey: ["org-overview"], queryFn: api.orgOverview });
  const devices = useQuery({
    queryKey: ["devices", {}, pseudonyms],
    queryFn: () => api.devices({ pseudonyms }),
  });
  const shown = useMemo(
    () =>
      (devices.data?.items ?? []).filter(
        (d) =>
          (!location || d.location === location) &&
          (!onlyRisky || d.open_findings > 0 || d.status === "shadow"),
      ),
    [devices.data, location, onlyRisky],
  );
  const elements = useMemo(
    () => buildElements(overview.data?.units ?? [], shown),
    [overview.data, shown],
  );

  useEffect(() => {
    if (!box.current || elements.length === 0) return;
    const cy = cytoscape({
      container: box.current,
      elements,
      style: MAP_STYLE,
      layout: { name: "preset", padding: 24 },
      minZoom: 0.3,
      maxZoom: 2.5,
      wheelSensitivity: 0.3,
    });
    cy.on("tap", "node.device", (event) => navigate(`/urzadzenia/${event.target.id()}`));
    cy.on("mouseover", "node.device", (event) => {
      if (box.current) box.current.style.cursor = "pointer";
      event.target.addClass("highlight");
    });
    cy.on("mouseout", "node.device", (event) => {
      if (box.current) box.current.style.cursor = "";
      event.target.removeClass("highlight");
    });
    graph.current = cy;
    return () => {
      cy.destroy();
      graph.current = null;
    };
  }, [elements, navigate]);

  const locations = overview.data?.locations ?? [];
  return (
    <>
      <PageHeader
        title="Mapa organizacji"
        description="Działy i ich urządzenia. Kolor to najwyższe ryzyko, większa kropka to więcej zagrożeń. Kliknij urządzenie, żeby otworzyć jego kartę."
      />
      <QueryState
        isPending={overview.isPending || devices.isPending}
        error={overview.error ?? devices.error}
        empty={false}
        emptyText=""
      />
      <Card data-demo="map">
        <div className="flex flex-wrap items-center gap-4 border-b border-border p-3 text-sm">
          <select
            value={location}
            onChange={(event) => setLocation(event.target.value)}
            aria-label="Lokalizacja"
            className="h-9 rounded-md border border-border bg-card px-2"
          >
            <option value="">Wszystkie lokalizacje</option>
            {locations.map((loc) => (
              <option key={loc.id} value={loc.name}>
                {loc.name} ({loc.devices})
              </option>
            ))}
          </select>
          <label className="flex cursor-pointer items-center gap-2">
            <input
              type="checkbox"
              checked={onlyRisky}
              onChange={(event) => setOnlyRisky(event.target.checked)}
              className="size-4"
            />
            Tylko z zagrożeniami i nieznane
          </label>
          <span className="text-muted-foreground tabular-nums">{shown.length} urządzeń</span>
          <button
            type="button"
            className="ml-auto text-sm underline"
            onClick={() => graph.current?.fit(undefined, 24)}
          >
            Dopasuj widok
          </button>
        </div>
        <div
          ref={box}
          className="h-[560px] w-full"
          role="img"
          aria-label={`Mapa ${shown.length} urządzeń w działach. Ta sama lista jest w tabeli urządzeń.`}
        />
        <CardContent className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-border pt-3 text-xs">
          {LEGEND.map(([label, color]) => (
            <span key={label} className="inline-flex items-center gap-1.5">
              <span className="size-3 rounded-full" style={{ background: color }} aria-hidden />
              {label}
            </span>
          ))}
          <span className="inline-flex items-center gap-1.5">
            <span className="size-3 rotate-45 bg-slate-400" aria-hidden /> Dostępne z internetu
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="size-3 rounded-full border-2 border-dashed border-amber-600" aria-hidden />
            Nieznane (nie ma go w CMDB, AD ani MDM)
          </span>
          <Link className="ml-auto underline" to="/urzadzenia">
            Widok tabeli
          </Link>
        </CardContent>
      </Card>
    </>
  );
}
