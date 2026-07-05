// CAP provider: turns the red-team engine into a paid, callable CROO agent.
//
// Lifecycle (CROO Agent Protocol):
//   NegotiationCreated -> acceptNegotiation   (agree to terms, only if a target was given)
//   OrderPaid          -> run red-team -> deliverOrder(report)   (escrow releases on Clear)
//
// NOTE ON SDK SHAPE: the CROO docs show `new AgentClient(config, sdkKey)` and
// `stream.on(EventType.NegotiationCreated | EventType.OrderPaid, ...)` plus
// `acceptNegotiation`, `rejectNegotiation`, `deliverOrder`. The exact way to
// obtain the event stream and the exact payload field names are not fully
// documented — the spots that must be confirmed against @croo-network/sdk are
// marked `TODO(sdk)`. The red-team engine itself (src/*) is SDK-independent and
// fully tested, so only this thin adapter needs to track the live SDK.
import "dotenv/config";
import { AgentClient, EventType } from "@croo-network/sdk";
import { runRedTeam } from "./redteam.js";
import { renderMarkdown } from "./report.js";
import { httpProbe } from "./probe.js";

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var ${name} (see .env.example)`);
  return v;
}

const client = new AgentClient(
  { apiUrl: required("CROO_API_URL"), wsUrl: required("CROO_WS_URL") },
  required("CROO_SDK_KEY"),
);

// The buyer must supply the agent endpoint to test. This is our consent
// boundary: no target_url -> no scan. Only ever probe what the buyer hands us.
function targetFrom(evt: any): string | undefined {
  return evt?.payload?.target_url ?? evt?.order?.payload?.target_url ?? evt?.negotiation?.payload?.target_url;
}

// TODO(sdk): confirm how the stream is obtained (client.stream() / client.events() / client.subscribe()).
const stream = (client as any).stream();

stream.on(EventType.NegotiationCreated, async (e: any) => {
  if (!targetFrom(e)) {
    await client.rejectNegotiation(e.negotiation_id, "missing target_url (consent required)");
    return;
  }
  await client.acceptNegotiation(e.negotiation_id);
  console.log(`accepted negotiation ${e.negotiation_id}`);
});

stream.on(EventType.OrderPaid, async (e: any) => {
  const target = targetFrom(e);
  if (!target) return; // should not happen — negotiation gated on it
  console.log(`order ${e.order_id} paid — red-teaming ${target}`);

  const report = await runRedTeam(httpProbe(target), { target });

  // TODO(sdk): confirm deliverable field names accepted by deliverOrder.
  await client.deliverOrder(e.order_id, {
    deliverable_text: renderMarkdown(report),
    deliverable_json: report,
  });
  console.log(`delivered order ${e.order_id} — grade ${report.grade} (${report.vulnerabilities} vulns)`);
});

console.log("Jailbreak-My-Agent provider online. Waiting for CAP orders…");
