import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

const dateTime = new Intl.DateTimeFormat("pl-PL", { dateStyle: "medium", timeStyle: "medium" });

export function formatDateTime(iso: string): string {
  return dateTime.format(new Date(iso));
}
