import { lookup as dnsLookup } from "node:dns";
import { Agent, fetch as undiciFetch, type Response as UndiciResponse } from "undici";
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
  if (s.startsWith("::ffff:")) {
    // v4-mapped: tail may be dotted (::ffff:127.0.0.1) or hex (::ffff:7f00:1 =
    // 127.0.0.1). Normalize hex groups to dotted; fail CLOSED (block) if unparseable.
    const tail = s.slice(7);
    if (tail.includes(".")) return isPrivateIp(tail);
    const g = tail.split(":").filter(Boolean);
    if (g.length !== 2) return true;
    const hi = parseInt(g[0], 16);
    const lo = parseInt(g[1], 16);
    if (Number.isNaN(hi) || Number.isNaN(lo)) return true;
    return isPrivateIp([(hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255].join("."));
  }
  return false;
}

type LookupCb = (
  err: NodeJS.ErrnoException | null,
  address?: string | Array<{ address: string; family: number }>,
  family?: number,
) => void;

/**
 * A DNS lookup that refuses to resolve to any private address. Used as the
 * connector's lookup, so the IP that is validated is the exact IP the socket
 * connects to — this closes the DNS-rebinding TOCTOU that a separate
 * pre-flight check would leave open. TLS servername (SNI/cert) is preserved
 * because the connection still targets the original hostname.
 */
export function guardedLookup(hostname: string, options: any, cb: LookupCb): void {
  const opts = typeof options === "object" && options ? options : { family: options };
  dnsLookup(hostname, { all: true, family: opts.family || 0, hints: opts.hints }, (err, addresses) => {
    if (err) return cb(err);
    const list = Array.isArray(addresses) ? addresses : [];
    if (!list.length) return cb(new Error(`no address for ${hostname}`));
    for (const a of list) {
      if (isPrivateIp(a.address)) {
        return cb(
          Object.assign(new Error(`blocked private address for ${hostname}: ${a.address}`), {
            code: "EBLOCKED",
          }),
        );
      }
    }
    if (opts.all) return cb(null, list);
    cb(null, list[0].address, list[0].family);
  });
}

// One dispatcher, reused: every request through it resolves via guardedLookup.
const secureAgent = new Agent({ connect: { lookup: guardedLookup as any } });

/**
 * Reject anything that isn't a public http(s) endpoint. A cheap pre-flight check
 * at the boundary; the connector's guardedLookup is the airtight enforcement.
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
  await new Promise<void>((resolve, reject) => {
    guardedLookup(host, {}, (err) => (err ? reject(err) : resolve()));
  });
}

// Read at most maxBytes of a response body so a hostile target can't exhaust
// memory with a giant reply. Exported for unit testing (the byte cap is a DoS
// boundary); takes a minimal reader-shaped object, not necessarily a real Response.
export async function readCapped(res: UndiciResponse, maxBytes: number): Promise<string> {
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
 * Extract the agent's reply text from a raw HTTP body: prefer common JSON reply
 * fields (output / response / text / deliverable_text), else fall back to the raw
 * body. This is what the detectors actually see, so a wrong pick mis-scores every
 * attack — kept pure and unit-tested.
 */
export function pickResponseField(text: string): string {
  try {
    const j = JSON.parse(text);
    return String(j.output ?? j.response ?? j.text ?? j.deliverable_text ?? text);
  } catch {
    return text;
  }
}

/**
 * HTTP adapter: POST {input} to the target agent's endpoint and read the reply.
 * All connections go through secureAgent, which pins to a validated public IP.
 * Buyers pass their agent's URL in the order payload (see agent.ts).
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
      const res = await undiciFetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ [field]: input }),
        signal: ctrl.signal,
        redirect: "error", // don't let a redirect bounce us to an internal host
        dispatcher: secureAgent, // pins connection to a validated public IP
      });
      // Non-2xx = the request didn't reach a working agent. Treat as an error (an
      // unmeasured probe), NOT as an agent reply — otherwise a target that 500s
      // everything scores as "resisted all probes" (a falsely good grade), and an
      // error page's text could false-positive a leak detector.
      if (!res.ok) {
        await res.body?.cancel().catch(() => {});
        throw new Error(`target returned HTTP ${res.status}`);
      }
      return pickResponseField(await readCapped(res, maxBytes));
    } finally {
      clearTimeout(timer);
    }
  };
}
