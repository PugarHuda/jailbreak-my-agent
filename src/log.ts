import type { Logger } from "@croo-network/sdk";

// The SDK logs the WebSocket URL on every connect/reconnect, and that URL carries
// ?key=<CROO_SDK_KEY>. Passed as-is to console it leaks the key into stdout / log
// sinks / demo recordings. This logger scrubs any key= param before printing.
const scrub = (s: string): string =>
  s.replace(/([?&](?:key|sdk[_-]?key)=)[^&\s"']+/gi, "$1REDACTED");

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

export { scrub as _scrubForTest };
