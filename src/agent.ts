// CAP provider: turns the red-team engine into a paid, callable CROO agent.
//
// Lifecycle (CROO Agent Protocol), wired to the official @croo-network/sdk shapes:
//   NegotiationCreated -> acceptNegotiation, stash the target by order id
//   OrderPaid          -> run red-team -> deliverOrder(report)
//
// The red-team engine (src/*) is SDK-independent and unit-tested. This adapter
// mirrors examples/provider.ts from the CROO node-sdk.
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
  required("CROO_SDK_KEY"),
);

// The buyer must supply the endpoint to test in `requirements`
// (e.g. '{"target_url":"https://my-agent/invoke"}'). No target -> no scan.
function targetFrom(e: any): string | undefined {
  const raw = e?.requirements ?? e?.payload ?? "";
  if (typeof raw === "object") return raw.target_url;
  try {
    return JSON.parse(raw).target_url;
  } catch {
    return undefined;
  }
}

const pending = new Map<string, string>(); // orderId -> target_url

const stream = await client.connectWebSocket();

stream.on(EventType.NegotiationCreated, async (e: any) => {
  const target = targetFrom(e);
  if (!target) {
    await client.rejectNegotiation(e.negotiation_id, "missing target_url (consent required)");
    return;
  }
  const res: any = await client.acceptNegotiation(e.negotiation_id);
  const orderId = res?.order?.orderId ?? res?.order?.order_id;
  if (orderId) pending.set(String(orderId), target);
  console.log(`accepted negotiation ${e.negotiation_id} -> order ${orderId}`);
});

stream.on(EventType.OrderPaid, async (e: any) => {
  const target = pending.get(String(e.order_id)) ?? targetFrom(e);
  if (!target) return;
  console.log(`order ${e.order_id} paid — red-teaming ${target}`);

  const report = await runRedTeam(httpProbe(target), { target });

  await client.deliverOrder(e.order_id, {
    deliverableType: DeliverableType.Text,
    deliverableText: renderMarkdown(report),
  });
  pending.delete(String(e.order_id));
  console.log(`delivered order ${e.order_id} — grade ${report.grade} (${report.vulnerabilities} vulns)`);
});

console.log("Jailbreak-My-Agent provider online. Waiting for CAP orders…");
