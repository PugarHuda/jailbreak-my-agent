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
import { httpProbe } from "./probe.js";

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
  process.env.CROO_SDK_KEY || required("CROO_API_KEY"),
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
    let target = pending.get(orderId);
    if (!target) {
      const order = await client.getOrder(orderId);
      target = targetFrom((await client.getNegotiation(order.negotiationId)).requirements);
    }
    if (!target) return;
    console.log(`order ${orderId} paid — red-teaming ${target}`);

    const report = await runRedTeam(httpProbe(target), { target });

    await client.deliverOrder(orderId, {
      deliverableType: DeliverableType.Text,
      deliverableText: renderMarkdown(report),
    });
    pending.delete(orderId);
    console.log(`delivered order ${orderId} — grade ${report.grade} (${report.vulnerabilities} vulns)`);
  } catch (err) {
    console.error("orderPaid handler error:", err);
  }
});

console.log("Jailbreak-My-Agent provider online. Waiting for CAP orders…");
