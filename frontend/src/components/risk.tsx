import { Badge } from "@/components/ui/badge";
import type { RiskLevel } from "@/lib/api";
import { cn } from "@/lib/utils";

const LEVEL_STYLE: Record<RiskLevel, string> = {
  krytyczny: "border-red-200 bg-red-50 text-risk-critical",
  wysoki: "border-orange-200 bg-orange-50 text-risk-high",
  średni: "border-amber-200 bg-amber-50 text-risk-medium",
  niski: "border-green-200 bg-green-50 text-risk-low",
};

const LEVEL_BAR: Record<RiskLevel, string> = {
  krytyczny: "bg-risk-critical",
  wysoki: "bg-risk-high",
  średni: "bg-risk-medium",
  niski: "bg-risk-low",
};

/** Poziom ryzyka zawsze z tekstem i liczbą, nigdy samym kolorem. */
export function RiskBadge({ level, score }: { level: RiskLevel; score?: number }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-semibold whitespace-nowrap",
        LEVEL_STYLE[level],
      )}
    >
      {score !== undefined && <span className="tabular-nums">{score.toFixed(1)}</span>}
      <span className="capitalize">{level}</span>
    </span>
  );
}

export function RiskBar({ level, value }: { level: RiskLevel; value: number }) {
  return (
    <div className="h-2 w-full rounded-full bg-muted" aria-hidden>
      <div
        className={cn("h-2 rounded-full", LEVEL_BAR[level])}
        style={{ width: `${Math.max(0, Math.min(100, value))}%` }}
      />
    </div>
  );
}

export function KevBadge() {
  return (
    <Badge variant="danger" title="Podatność jest w katalogu CISA KEV: aktywnie wykorzystywana">
      KEV
    </Badge>
  );
}
