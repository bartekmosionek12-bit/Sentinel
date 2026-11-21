import type { InputHTMLAttributes, SelectHTMLAttributes } from "react";

import { cn } from "@shared/lib/utils";

const fieldClass =
  "h-8 w-full rounded-sm border border-border bg-field px-2.5 text-sm focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-primary";

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn(fieldClass, className)} {...props} />;
}

export function Select({ className, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className={cn(fieldClass, className)} {...props} />;
}
