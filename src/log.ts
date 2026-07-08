import type { Logger } from "@croo-network/sdk";

// The SDK key can reach stdout several ways: the SDK logs the ws URL (?key=<KEY>),
// and the app's own console.error(err) may print an SDK Error whose message/stack
// carries that URL. Redact the key token itself (strongest — catches it anywhere)
// plus the common query-param / bearer / header shapes.
const scrub = (s: string): string =>
  s
    .replace(/croo_sk_[A-Za-z0-9]+/gi, "croo_sk_REDACTED")
    .replace(/([?&](?:key|sdk[_-]?key)=)[^&\s"']+/gi, "$1REDACTED")
    .replace(/(bearer\s+|x-sdk-key["':\s]+)[^\s"',}]+/gi, "$1REDACTED");

const clean = (a: unknown): unknown => {
  try {
    if (typeof a === "string") return scrub(a);
    if (a instanceof Error) return scrub(a.stack ?? a.message ?? String(a));
    if (a && typeof a === "object") return JSON.parse(scrub(JSON.stringify(a)));
  } catch {
    /* fall through to a scrubbed string form — never leak, never throw */
  }
  return scrub(String(a));
};

export const safeLogger: Logger = {
  info: (m, ...a) => console.info(scrub(m), ...a.map(clean)),
  warn: (m, ...a) => console.warn(scrub(m), ...a.map(clean)),
  error: (m, ...a) => console.error(scrub(m), ...a.map(clean)),
  debug: (m, ...a) => console.debug(scrub(m), ...a.map(clean)),
};

// Route ALL console output through the scrubber, so the app's own error logs
// (console.error("…:", err) with an SDK Error) can't leak the key either. Call
// once at process startup.
export function installConsoleScrub(): void {
  for (const level of ["log", "info", "warn", "error", "debug"] as const) {
    const orig = console[level].bind(console);
    console[level] = (...args: unknown[]) => orig(...args.map(clean));
  }
}

export { scrub as _scrubForTest };
