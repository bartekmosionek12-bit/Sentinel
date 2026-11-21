import type { InputHTMLAttributes, SelectHTMLAttributes } from "react";

import { cn } from "@shared/lib/utils";

const fieldClass =
  "h-9 w-full rounded-md border border-border bg-card px-3 text-sm focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-primary";

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn(fieldClass, className)} {...props} />;
}

export function Select({ className, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className={cn(fieldClass, className)} {...props} />;
}
