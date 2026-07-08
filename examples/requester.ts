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

const client = new AgentClient(
  {
    baseURL: required("CROO_API_URL"),
    wsURL: required("CROO_WS_URL"),
    rpcURL: process.env.BASE_RPC_URL,
    logger: safeLogger,
  },
  required("CROO_SDK_KEY"),
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
