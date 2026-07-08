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
import { AgentClient, EventType, DeliverableType } from "@croo-network/sdk";
import { runRedTeam } from "./redteam.js";
import { renderMarkdown } from "./report.js";
import { httpProbe, assertPublicUrl } from "./probe.js";

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
  },
  required("CROO_SDK_KEY"),
);

// Buyer supplies the endpoint to test in `requirements`
// (e.g. '{"target_url":"https://my-agent/invoke"}'). No target -> no scan.
function targetFrom(requirements: string | undefined): string | undefined {
  if (!requirements) return undefined;
  try {
    return JSON.parse(requirements).target_url;
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

stream.on(EventType.OrderPaid, async (e) => {
  try {
    const orderId = e.order_id!;
    if (handledOrders.has(orderId)) return;
    handledOrders.add(orderId);
    let target = pending.get(orderId);
    if (!target) {
      const order = await client.getOrder(orderId);
      target = targetFrom((await client.getNegotiation(order.negotiationId)).requirements);
    }
    if (!target) return;
    console.log(`order ${orderId} paid — red-teaming ${target}`);

    const report = await runRedTeam(httpProbe(target), { target });

    // Order is already paid — a transient deliver failure must not silently lose
    // the buyer's report (the order is marked handled, so a replay won't retry).
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
      console.error(`⚠️  order ${orderId} PAID but UNDELIVERED after retries — re-deliver manually.`);
      return;
    }
    pending.delete(orderId);
    console.log(`delivered order ${orderId} — grade ${report.grade} (${report.vulnerabilities} vulns)`);
  } catch (err) {
    console.error("orderPaid handler error:", err);
  }
});

console.log("Jailbreak-My-Agent provider online. Waiting for CAP orders…");
