import { lookup } from "node:dns/promises";
import type { Probe } from "./redteam.js";

/**
 * True if an IP literal is loopback / private / link-local / unique-local /
 * cloud-metadata — i.e. must never be reached from a paid scan (SSRF guard).
 */
export function isPrivateIp(ip: string): boolean {
  const v4 = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // link-local + cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    return false;
  }
  const s = ip.toLowerCase();
  if (s === "::1" || s === "::") return true;
  if (s.startsWith("fe80")) return true; // link-local
  if (s.startsWith("fc") || s.startsWith("fd")) return true; // unique-local
  if (s.startsWith("::ffff:")) return isPrivateIp(s.slice(7)); // v4-mapped
  return false;
}

/**
 * Reject anything that isn't a public http(s) endpoint. Resolves the host so a
 * public hostname pointing at a private IP is still blocked. Throws on violation.
 */
export async function assertPublicUrl(raw: string): Promise<void> {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`invalid URL: ${raw}`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error(`unsupported scheme: ${u.protocol}`);
  }
  const host = u.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    throw new Error(`blocked host: ${host}`);
  }
  const addrs = await lookup(host, { all: true });
  for (const { address } of addrs) {
    if (isPrivateIp(address)) {
      throw new Error(`blocked private address for ${host}: ${address}`);
    }
  }
}

// Read at most maxBytes of a response body so a hostile target can't exhaust
// memory with a giant reply.
async function readCapped(res: Response, maxBytes: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return (await res.text()).slice(0, maxBytes);
  const chunks: Uint8Array[] = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      received += value.length;
      if (received >= maxBytes) {
        await reader.cancel();
        break;
      }
    }
  }
  return Buffer.concat(chunks).toString("utf8").slice(0, maxBytes);
}

/**
 * HTTP adapter: POST {input} to the target agent's endpoint and read the reply.
 * Tries common response fields before falling back to raw text.
 *
 * Buyers pass their agent's URL in the order payload (see agent.ts). Validate it
 * with assertPublicUrl at the boundary before building a probe.
 */
export function httpProbe(
  url: string,
  opts: { field?: string; timeoutMs?: number; maxBytes?: number } = {},
): Probe {
  const field = opts.field ?? "input";
  const timeoutMs = opts.timeoutMs ?? 20_000;
  const maxBytes = opts.maxBytes ?? 256_000;

  return async (input) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ [field]: input }),
        signal: ctrl.signal,
        redirect: "error", // don't let a redirect bounce us to an internal host
      });
      const text = await readCapped(res, maxBytes);
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
