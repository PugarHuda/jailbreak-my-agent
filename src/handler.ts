// The scan-order-handling core, isolated from the live-daemon wiring in agent.ts
// so it can be unit-tested with a mock client (no WS, no network scan). agent.ts
// is now a thin env+WS wire. Every guard here encodes an idempotency/retry
// property; don't drop them.
import { DeliverableType, OrderStatus, NegotiationStatus } from "@croo-network/sdk";
import type { AgentClient, Order, Negotiation } from "@croo-network/sdk";
import { runRedTeam, type Report } from "./redteam.js";
import { renderMarkdown } from "./report.js";
import { httpProbe, assertPublicUrl } from "./probe.js";

// Buyer supplies the endpoint to test in `requirements`
// (e.g. '{"target_url":"https://my-agent/invoke"}'). No target -> no scan.
export function targetFrom(requirements: string | undefined): string | undefined {
  if (!requirements) return undefined;
  try {
    const t = JSON.parse(requirements).target_url;
    return typeof t === "string" ? t : undefined; // a non-string target_url can't be scanned
  } catch {
    return undefined;
  }
}

const realSleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const UNDELIVERED = new Set<string>([
  OrderStatus.Paid,
  OrderStatus.Delivering,
  OrderStatus.DeliverFailed,
]);

export interface ScanHandlerConfig {
  // Test seams — production defaults hit the network. Overridden in unit tests so
  // the order-handling logic runs with no real HTTP scan / no waits.
  scan?: (target: string) => Promise<Report>;
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Build the provider scan-order handlers over a client. Holds the per-process
 * idempotency state (pending / handledOrders); returns the entry points
 * (handlePaidOrder, reconcile) plus that state for inspection.
 */
export function createScanHandler(client: AgentClient, cfg: ScanHandlerConfig = {}) {
  const scan = cfg.scan ?? ((target: string) => runRedTeam(httpProbe(target), { target }));
  const sleep = cfg.sleep ?? realSleep;

  const pending = new Map<string, string>(); // orderId -> target_url
  // Idempotency: a replayed OrderPaid (WS buffer/reconnect) must not re-scan the
  // target or re-deliver.
  const handledOrders = new Set<string>();
  // Negotiations already accepted/rejected — guards the WS handler and the recovery
  // sweep from double-accepting the same negotiation.
  const handledNegotiations = new Set<string>();

  // Accept (or reject) a scan negotiation: require a target_url + pass the SSRF
  // pre-flight, else reject. Shared by the live WS NegotiationCreated handler and
  // the recovery sweep (a negotiation that arrived while the WS was down would
  // otherwise be dropped and never become an order). knownNeg is supplied by the
  // sweep (from listNegotiations) to skip a fetch.
  async function handleNegotiation(negId: string, knownNeg?: Negotiation) {
    if (handledNegotiations.has(negId)) return;
    handledNegotiations.add(negId);
    try {
      const neg = knownNeg ?? (await client.getNegotiation(negId));
      if (neg.status && neg.status !== NegotiationStatus.Pending) return; // already resolved
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
      handledNegotiations.delete(negId); // transient failure — allow a later retry
      console.error("negotiation handler error:", err);
    }
  }

  // Recover negotiations that arrived while the WS was disconnected: without this
  // the buyer's scan request is dropped and never becomes an order.
  async function reconcileNegotiations() {
    const negs: Negotiation[] = [];
    for (let page = 1; page <= 50; page++) {
      const batch = await client.listNegotiations({
        role: "provider",
        status: NegotiationStatus.Pending,
        page,
        pageSize: 100,
      });
      negs.push(...batch);
      if (!batch.length) break;
    }
    for (const n of negs) {
      if (handledNegotiations.has(n.negotiationId)) continue;
      console.log(`reconcile: recovering un-accepted negotiation ${n.negotiationId}`);
      await handleNegotiation(n.negotiationId, n).catch((err) =>
        console.error(`reconcile: negotiation ${n.negotiationId} failed:`, err),
      );
    }
  }

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

      const report = await scan(target);

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

  // Reconcile missed events: an OrderPaid that fires while the WS is disconnected
  // would leave the buyer paid with no scan/report. Sweep provider orders that are
  // paid but not yet delivered and process any not already handled.
  async function reconcile() {
    try {
      // First recover negotiations missed during a WS gap (accepting them creates
      // the orders the order-sweep below then processes). Its own catch: a
      // listNegotiations failure must NOT skip the paid-order sweep below — the two
      // recovery nets are independent.
      await reconcileNegotiations().catch((err) => console.error("reconcile negotiations error:", err));
      // Walk all pages; no .catch(()=>[]) — a persistent listOrders failure must
      // surface via the outer catch, not silently disable the recovery net.
      const orders: Order[] = [];
      for (let page = 1; page <= 50; page++) {
        const batch = await client.listOrders({ role: "provider", page, pageSize: 100 });
        orders.push(...batch);
        // Stop only on an empty page — NOT on `< pageSize`. The server may clamp
        // pageSize (the sibling public API caps at 50), so a short-but-nonempty page
        // is normal and a stuck order on a later page must still be swept.
        if (!batch.length) break;
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

  return { handlePaidOrder, handleNegotiation, reconcile, pending, handledOrders, handledNegotiations };
}
