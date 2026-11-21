import { sentinelApp } from "../vite.shared.ts";

export default sentinelApp("dashboard", Number(process.env.PORT ?? 5174));
