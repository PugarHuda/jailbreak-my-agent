// The scan-order-handling core, isolated from the live-daemon wiring in agent.ts
// so it can be unit-tested with a mock client (no WS, no network scan). agent.ts
// is now a thin env+WS wire. Every guard here encodes an idempotency/retry
// property; don't drop them.
import { DeliverableType, OrderStatus } from "@croo-network/sdk";
import type { AgentClient, Order } from "@croo-network/sdk";
import { runRedTeam, type Report } from "./redteam.js";
import { renderMarkdown } from "./report.js";
import { httpProbe } from "./probe.js";

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

  return { handlePaidOrder, reconcile, pending, handledOrders };
}
