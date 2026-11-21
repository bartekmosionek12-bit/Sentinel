import { cva, type VariantProps } from "class-variance-authority";
import {
  CircleAlert,
  CircleCheck,
  CircleDashed,
  CircleX,
  Info,
  type LucideIcon,
} from "lucide-react";
import type { HTMLAttributes } from "react";

import { cn } from "@shared/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-semibold whitespace-nowrap",
  {
    variants: {
      variant: {
        neutral: "border-border bg-muted text-foreground",
        ok: "border-green-200 bg-green-50 text-green-800",
        warn: "border-amber-200 bg-amber-50 text-amber-800",
        danger: "border-red-200 bg-red-50 text-red-800",
        info: "border-sky-200 bg-sky-50 text-sky-800",
      },
    },
    defaultVariants: { variant: "neutral" },
  },
);

/** Status nigdy nie jest oznaczany samym kolorem: każdy wariant ma też ikonę. */
const ICONS: Record<string, LucideIcon | null> = {
  neutral: CircleDashed,
  ok: CircleCheck,
  warn: CircleAlert,
  danger: CircleX,
  info: Info,
};

type BadgeProps = HTMLAttributes<HTMLSpanElement> &
  VariantProps<typeof badgeVariants> & { icon?: boolean };

export function Badge({ className, variant, icon = true, children, ...props }: BadgeProps) {
  const Icon = icon ? ICONS[variant ?? "neutral"] : null;
  return (
    <span className={cn(badgeVariants({ variant }), className)} {...props}>
      {Icon && <Icon className="size-3.5 shrink-0" aria-hidden />}
      {children}
    </span>
  );
}
