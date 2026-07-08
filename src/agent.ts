// CAP provider: turns the red-team engine into a paid, callable CROO agent.
//
// Lifecycle (CROO Agent Protocol), wired to the installed @croo-network/sdk types:
//   NegotiationCreated -> getNegotiation (for target_url) -> acceptNegotiation
//   OrderPaid          -> run red-team -> deliverOrder(report)
//
// The buyer's input lives on the Negotiation object (event carries only ids), so
// we fetch it with getNegotiation. The red-team engine (src/*) is SDK-independent
// and unit-tested.
import "dotenv/config";
import { AgentClient, EventType, DeliverableType, OrderStatus } from "@croo-network/sdk";
import type { Order } from "@croo-network/sdk";
import { runRedTeam } from "./redteam.js";
import { renderMarkdown } from "./report.js";
import { httpProbe, assertPublicUrl } from "./probe.js";
import { safeLogger, installConsoleScrub } from "./log.js";

// Scrub the SDK key out of ALL console output (app error logs too) before logging.
installConsoleScrub();

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var ${name} (see .env.example)`);
  return v;
}

const client = new AgentClient(
  {
    baseURL: required("CROO_API_URL"),
    wsURL: required("CROO_WS_URL"),
    rpcURL: process.env.BASE_RPC_URL,
    logger: safeLogger, // scrub the SDK key out of the logged ws url
  },
  required("CROO_SDK_KEY"),
);

// Buyer supplies the endpoint to test in `requirements`
// (e.g. '{"target_url":"https://my-agent/invoke"}'). No target -> no scan.
function targetFrom(requirements: string | undefined): string | undefined {
  if (!requirements) return undefined;
  try {
    const t = JSON.parse(requirements).target_url;
    return typeof t === "string" ? t : undefined; // a non-string target_url can't be scanned
  } catch {
    return undefined;
  }
}

const pending = new Map<string, string>(); // orderId -> target_url
// Idempotency: a replayed OrderPaid (WS buffer/reconnect) must not re-scan the
// target or re-deliver.
const handledOrders = new Set<string>();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const stream = await client.connectWebSocket();

stream.on(EventType.NegotiationCreated, async (e) => {
  try {
    const negId = e.negotiation_id!;
    const neg = await client.getNegotiation(negId);
    const target = targetFrom(neg.requirements);
    if (!target) {
      await client.rejectNegotiation(negId, "missing target_url (consent required)");
      return;
    }
    try {
      await assertPublicUrl(target); // SSRF guard: only scan public endpoints
    } catch (e) {
      await client.rejectNegotiation(negId, `target rejected: ${(e as Error).message}`);
      return;
    }
    const res = await client.acceptNegotiation(negId);
    pending.set(res.order.orderId, target);
    console.log(`accepted negotiation ${negId} -> order ${res.order.orderId}`);
  } catch (err) {
    console.error("negotiation handler error:", err);
  }
});

async function handlePaidOrder(orderId: string, knownOrder?: Order) {
  // Idempotency: skip a replayed OrderPaid / an order reconcile already grabbed.
  if (handledOrders.has(orderId)) return;
  handledOrders.add(orderId);
  try {
    const order = knownOrder ?? (await client.getOrder(orderId).catch(() => undefined));
    // Already delivered? A replayed OrderPaid after a restart must not re-scan/re-deliver.
    if (order?.deliveredAt) return;
    let target = pending.get(orderId);
    if (!target) {
      // No context and nothing spent here — un-mark so a later replay/sweep can retry.
      if (!order) {
        handledOrders.delete(orderId);
        return;
      }
      const neg = await client.getNegotiation(order.negotiationId);
      target = targetFrom(neg.requirements);
    }
    if (!target) {
      handledOrders.delete(orderId);
      return;
    }
    console.log(`order ${orderId} paid — red-teaming ${target}`);

    const report = await runRedTeam(httpProbe(target), { target });

    // Order is already paid — a transient deliver failure must not silently lose
    // the buyer's report. Re-scanning costs no money here (no sub-orders), so on a
    // failed deliver we un-mark and let reconcile retry the whole thing.
    const deliverableText = renderMarkdown(report);
    let delivered = false;
    for (let i = 0; i < 3; i++) {
      try {
        await client.deliverOrder(orderId, {
          deliverableType: DeliverableType.Text,
          deliverableText,
        });
        delivered = true;
        break;
      } catch (err) {
        console.error(`deliver attempt ${i + 1}/3 failed for order ${orderId}:`, err);
        if (i < 2) await sleep(2000);
      }
    }
    if (!delivered) {
      console.error(`⚠️  order ${orderId} PAID but UNDELIVERED after retries — reconcile will retry.`);
      handledOrders.delete(orderId);
      return;
    }
    pending.delete(orderId);
    console.log(`delivered order ${orderId} — grade ${report.grade} (${report.vulnerabilities} vulns)`);
  } catch (err) {
    handledOrders.delete(orderId); // pre-delivery failure (e.g. getNegotiation threw) — allow retry
    console.error("orderPaid handler error:", err);
  }
}

stream.on(EventType.OrderPaid, async (e) => {
  await handlePaidOrder(e.order_id!);
});

// Reconcile missed events: an OrderPaid that fires while the WS is disconnected
// would leave the buyer paid with no scan/report. Sweep provider orders that are
// paid but not yet delivered and process any not already handled. On startup + on
// an interval. ponytail: 60s poll; tighten if orders must clear faster.
const UNDELIVERED = new Set<string>([
  OrderStatus.Paid,
  OrderStatus.Delivering,
  OrderStatus.DeliverFailed,
]);
async function reconcile() {
  try {
    // Walk all pages; no .catch(()=>[]) — a persistent listOrders failure must
    // surface via the outer catch, not silently disable the recovery net.
    const orders: Order[] = [];
    for (let page = 1; page <= 50; page++) {
      const batch = await client.listOrders({ role: "provider", page, pageSize: 100 });
      orders.push(...batch);
      if (batch.length < 100) break;
    }
    const stuck = orders.filter(
      (o) => UNDELIVERED.has(o.status) && !o.deliveredAt && !handledOrders.has(o.orderId),
    );
    for (const o of stuck) {
      console.log(`reconcile: recovering paid-but-undelivered order ${o.orderId} (${o.status})`);
      await handlePaidOrder(o.orderId, o).catch((err) =>
        console.error(`reconcile: order ${o.orderId} failed:`, err),
      );
    }
  } catch (err) {
    console.error("reconcile error:", err);
  }
}

console.log("Jailbreak-My-Agent provider online. Waiting for CAP orders…");
console.log(`config: API=${process.env.CROO_API_URL} services offered on the Store; SSRF guard active.`);
await reconcile();
setInterval(reconcile, 60_000);
