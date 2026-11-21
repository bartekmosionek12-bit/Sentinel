/**
 * Sentek: postać asystenta (moduł 21 i film demo z modułu 22). Własny projekt: tarcza z
 * wizjerem, antena ze światełkiem i krótkie ręce. Pozy zmieniają ręce, oczy i usta; ruch
 * to tylko CSS (bez bibliotek), wyłączany przy `prefers-reduced-motion`.
 */
import type { SentekPose } from "@shared/lib/sentek";
import { cn } from "@shared/lib/utils";

export type { SentekPose };

// Kąt ręki od pionu w dół (stopnie, zgodnie z ruchem wskazówek zegara w SVG).
const ARMS: Record<SentekPose, { left: number; right: number }> = {
  idle: { left: 18, right: -18 },
  talk: { left: 22, right: -40 },
  wave: { left: 18, right: -150 },
  point_left: { left: 95, right: -18 },
  point_right: { left: 18, right: -95 },
  surprised: { left: 120, right: -120 },
  thumbs_up: { left: 18, right: -128 },
};

const BODY = "#2a78d6";
const BODY_DARK = "#1b5aa6";
const VISOR = "#0f2340";
const EYES = "#7fe3ff";
const LIGHT = "#f5b335";

function Arm({
  x,
  y,
  angle,
  hand,
  className,
}: {
  x: number;
  y: number;
  angle: number;
  hand: "open" | "point" | "thumb";
  className?: string;
}) {
  return (
    <g transform={`translate(${x} ${y}) rotate(${angle})`}>
      <g className={className}>
        <rect
          x={-5.5}
          y={-2}
          width={11}
          height={30}
          rx={5.5}
          fill={BODY_DARK}
        />
        <circle
          cx={0}
          cy={32}
          r={7.5}
          fill={BODY}
          stroke={BODY_DARK}
          strokeWidth={2}
        />
        {hand === "point" && (
          <rect
            x={-2.5}
            y={36}
            width={5}
            height={11}
            rx={2.5}
            fill={BODY}
            stroke={BODY_DARK}
            strokeWidth={1.5}
          />
        )}
        {hand === "thumb" && (
          <rect
            x={-3.5}
            y={33}
            width={7}
            height={13}
            rx={3.5}
            fill={BODY}
            stroke={BODY_DARK}
            strokeWidth={1.5}
          />
        )}
      </g>
    </g>
  );
}

function Mouth({ pose }: { pose: SentekPose }) {
  if (pose === "surprised")
    return <ellipse cx={60} cy={63} rx={4} ry={5} fill={EYES} />;
  if (pose === "talk")
    return (
      <ellipse
        className="sentek-mouth"
        cx={60}
        cy={63}
        rx={7}
        ry={3.5}
        fill={EYES}
      />
    );
  return (
    <path
      d="M51 61 Q60 68 69 61"
      fill="none"
      stroke={EYES}
      strokeWidth={3}
      strokeLinecap="round"
    />
  );
}

export function Sentek({
  pose = "idle",
  size = 96,
  animated = true,
  className,
  title = "Sentek",
}: {
  pose?: SentekPose;
  size?: number;
  animated?: boolean;
  className?: string;
  title?: string;
}) {
  const arms = ARMS[pose];
  const eye = pose === "surprised" ? 6.5 : 5;
  return (
    <svg
      viewBox="-22 0 164 140"
      width={size}
      height={(size * 140) / 164}
      role="img"
      aria-label={title}
      data-pose={pose}
      className={cn("sentek", animated && "sentek-animated", className)}
    >
      <g className="sentek-body">
        {/* antena */}
        <line
          x1={60}
          y1={22}
          x2={60}
          y2={9}
          stroke={BODY_DARK}
          strokeWidth={3}
          strokeLinecap="round"
        />
        <circle className="sentek-light" cx={60} cy={7} r={4.5} fill={LIGHT} />
        {/* ręce za tarczą */}
        <Arm
          x={24}
          y={66}
          angle={arms.left}
          hand={pose === "point_left" ? "point" : "open"}
        />
        <Arm
          x={96}
          y={66}
          angle={arms.right}
          hand={
            pose === "point_right"
              ? "point"
              : pose === "thumbs_up"
                ? "thumb"
                : "open"
          }
          className={pose === "wave" ? "sentek-wave" : undefined}
        />
        {/* tarcza */}
        <path
          d="M18 28 Q60 12 102 28 L102 72 Q102 112 60 132 Q18 112 18 72 Z"
          fill={BODY}
          stroke={BODY_DARK}
          strokeWidth={3}
          strokeLinejoin="round"
        />
        <path
          d="M30 34 Q60 24 90 34"
          fill="none"
          stroke="#ffffff"
          strokeOpacity={0.35}
          strokeWidth={3}
          strokeLinecap="round"
        />
        {/* wizjer z oczami */}
        <rect x={32} y={36} width={56} height={38} rx={15} fill={VISOR} />
        <g className="sentek-eyes">
          <ellipse cx={47} cy={51} rx={eye} ry={eye + 1} fill={EYES} />
          <ellipse cx={73} cy={51} rx={eye} ry={eye + 1} fill={EYES} />
        </g>
        <Mouth pose={pose} />
        {/* znak na piersi: dziurka od klucza */}
        <circle cx={60} cy={96} r={9} fill="#ffffff" fillOpacity={0.9} />
        <circle cx={60} cy={94} r={3} fill={BODY_DARK} />
        <path d="M58 95 L62 95 L63 102 L57 102 Z" fill={BODY_DARK} />
      </g>
    </svg>
  );
}
