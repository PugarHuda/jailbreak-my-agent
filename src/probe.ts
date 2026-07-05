import type { Probe } from "./redteam.js";

/**
 * HTTP adapter: POST {input} to the target agent's endpoint and read the reply.
 * Tries common response fields before falling back to raw text.
 *
 * Buyers pass their agent's URL in the order payload (see agent.ts). This is the
 * consent boundary: we only probe an endpoint the buyer explicitly supplied.
 */
export function httpProbe(
  url: string,
  opts: { field?: string; timeoutMs?: number } = {},
): Probe {
  const field = opts.field ?? "input";
  const timeoutMs = opts.timeoutMs ?? 20_000;

  return async (input) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ [field]: input }),
        signal: ctrl.signal,
      });
      const text = await res.text();
      try {
        const j = JSON.parse(text);
        return String(
          j.output ?? j.response ?? j.text ?? j.deliverable_text ?? text,
        );
      } catch {
        return text;
      }
    } finally {
      clearTimeout(timer);
    }
  };
}
