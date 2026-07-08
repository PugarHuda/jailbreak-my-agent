// Buyer simulator — hires Jailbreak-My-Agent over CAP to demo the full lifecycle:
//   negotiate -> (agent accepts) OrderCreated -> pay -> OrderCompleted -> download
//
// Set CROO_TARGET_SERVICE_ID to the `redteam_scan` service id, then:
//   npm run buyer -- https://my-agent.example.com/invoke
import "dotenv/config";
import { AgentClient, EventType } from "@croo-network/sdk";
import { safeLogger } from "../src/log.js";

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var ${name} (see .env.example)`);
  return v;
}

// The buyer must be a DIFFERENT identity than the scanner, or the platform sees a
// self-order (likely rejected, and a self-trade that's ineligible for rewards).
// It also collides on the WS: one connection per SDK key — running this with the
// agent's own key while `npm start` is up drops one of them. Set BUYER_SDK_KEY to
// another agent's key for a real order; falling back to CROO_SDK_KEY is a local
// flow check only.
const buyerKey = process.env.BUYER_SDK_KEY || required("CROO_SDK_KEY");
if (!process.env.BUYER_SDK_KEY) {
  console.warn(
    "⚠️  BUYER_SDK_KEY not set — using the agent's own key. This is a SELF-ORDER:\n" +
      "    fine for a local flow check, but the platform may reject it, it does NOT\n" +
      "    count toward rewards, and it collides on the WS if the agent is running.\n" +
      "    Use a separate agent's key for a real buyer.",
  );
}

const client = new AgentClient(
  {
    baseURL: required("CROO_API_URL"),
    wsURL: required("CROO_WS_URL"),
    rpcURL: process.env.BASE_RPC_URL,
    logger: safeLogger,
  },
  buyerKey,
);

const serviceId = required("CROO_TARGET_SERVICE_ID");
const targetUrl = process.argv[2];
if (!targetUrl) {
  console.error("usage: npm run buyer -- <target-url>");
  process.exit(2);
}

const stream = await client.connectWebSocket();

stream.on(EventType.OrderCreated, async (e: any) => {
  console.log(`order ${e.order_id} created — paying…`);
  await client.payOrder(e.order_id);
});

stream.on(EventType.OrderCompleted, async (e: any) => {
  const delivery: any = await client.getDelivery(e.order_id);
  console.log("\n=== Security report delivered ===\n");
  console.log(delivery.deliverableText);
  process.exit(0);
});

const neg: any = await client.negotiateOrder({
  serviceId,
  requirements: JSON.stringify({ target_url: targetUrl }),
});
console.log(`negotiation sent to scan: ${targetUrl}`, neg?.negotiationId ?? "");
