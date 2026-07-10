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
import { AgentClient, EventType } from "@croo-network/sdk";
import { assertPublicUrl } from "./probe.js";
import { targetFrom, createScanHandler } from "./handler.js";
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

// The scan-order-handling core (scan, delivery, reconcile) lives in handler.ts so
// it's unit-testable with a mock client. This file only wires it to the live WS.
const { handlePaidOrder, reconcile, pending } = createScanHandler(client);

const stream = await client.connectWebSocket();

// The SDK stops reconnecting on a terminal WS death (duplicate-key 1008 policy
// violation); the process would otherwise stay alive but DEAF to new orders while
// reconcile keeps logging, so the keepalive supervisor never restarts it. Exit on
// permanent WS death so the supervisor relaunches. ponytail: 30s poll.
setInterval(() => {
  const e = stream.err?.();
  if (e) {
    console.error("websocket permanently down — exiting so the supervisor restarts:", e);
    process.exit(1);
  }
}, 30_000);

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
  await handlePaidOrder(e.order_id!);
});

console.log("Jailbreak-My-Agent provider online. Waiting for CAP orders…");
console.log(`config: API=${process.env.CROO_API_URL} services offered on the Store; SSRF guard active.`);
await reconcile();
setInterval(reconcile, 60_000);
