import assert from "node:assert/strict";
import { createScanHandler, targetFrom } from "../src/handler.js";
import type { Report } from "../src/redteam.js";

// The provider scan-order path (handler.ts) drives a paid scan then delivers the
// report. It was previously only integration-tested against the live network.
// These are unit tests with a mocked client + injected scan — no WS, no HTTP.

interface ClientOverrides {
  order?: any;
  getOrderThrows?: boolean;
  negotiation?: any;
  getNegotiationThrows?: boolean;
  deliverThrows?: boolean;
  listOrders?: any[];
}

function makeClient(o: ClientOverrides = {}) {
  const calls = { getOrder: 0, getNegotiation: 0, deliver: 0, listOrders: 0 };
  const delivered: any[] = [];
  const client = {
    async getOrder() {
      calls.getOrder++;
      if (o.getOrderThrows) throw new Error("getOrder boom");
      return o.order;
    },
    async getNegotiation() {
      calls.getNegotiation++;
      if (o.getNegotiationThrows) throw new Error("getNegotiation boom");
      return o.negotiation ?? { requirements: JSON.stringify({ target_url: "https://recovered.example" }) };
    },
    async deliverOrder(_id: string, payload: any) {
      calls.deliver++;
      if (o.deliverThrows) throw new Error("deliver boom");
      delivered.push(payload);
    },
    async listOrders(q: any) {
      calls.listOrders++;
      // page-aware: reconcile stops on an empty page, so serve rows on page 1 only.
      return (q?.page ?? 1) > 1 ? [] : (o.listOrders ?? []);
    },
  };
  return { client: client as any, calls, delivered };
}

// A scan spy: records the targets scanned and returns a canned report.
function makeScan(grade: Report["grade"] = "A") {
  const seen: string[] = [];
  const report = { score: 100, grade, summary: "s", totalAttacks: 8, vulnerabilities: 0, findings: [], evaluated: true, reflects: false } as Report;
  const scan = async (target: string) => {
    seen.push(target);
    return report;
  };
  return { scan, seen };
}

const cfg = (scan: (t: string) => Promise<Report>) => ({ scan, sleep: async () => {} });

// ── targetFrom parsing ───────────────────────────────────────────────────────
assert.equal(targetFrom(undefined), undefined, "no requirements -> no target");
assert.equal(targetFrom('{"target_url":"https://a"}'), "https://a", "target_url parsed");
assert.equal(targetFrom('{"target_url":123}'), undefined, "non-string target_url rejected");
assert.equal(targetFrom("not json"), undefined, "unparseable requirements -> no target");
assert.equal(targetFrom("{}"), undefined, "missing target_url -> undefined");

// ── 1. Happy path: scan the target, then deliver the report ──────────────────
{
  const { scan, seen } = makeScan("B");
  const { client, calls, delivered } = makeClient({ order: { orderId: "o1", negotiationId: "n1" } });
  const h = createScanHandler(client, cfg(scan));
  h.pending.set("o1", "https://victim.example");
  await h.handlePaidOrder("o1");

  assert.deepEqual(seen, ["https://victim.example"], "scanned the pending target exactly once");
  assert.equal(calls.deliver, 1, "delivered once");
  assert.ok(delivered[0].deliverableText.includes("Grade B"), "report rendered into the delivery");
  assert.ok(h.handledOrders.has("o1"), "marked handled");
  assert.ok(!h.pending.has("o1"), "pending cleared after delivery");
}

// ── 2. Idempotency: a replayed OrderPaid must not re-scan / re-deliver ────────
{
  const { scan, seen } = makeScan();
  const { client, calls } = makeClient({ order: { orderId: "o2", negotiationId: "n2" } });
  const h = createScanHandler(client, cfg(scan));
  h.pending.set("o2", "https://victim.example");
  await h.handlePaidOrder("o2");
  await h.handlePaidOrder("o2"); // replay

  assert.equal(seen.length, 1, "target NOT re-scanned on replay");
  assert.equal(calls.deliver, 1, "report NOT re-delivered on replay");
}

// ── 3. Deliver fails: un-mark handled so reconcile can retry the whole scan ───
{
  const { scan, seen } = makeScan();
  const { client, calls } = makeClient({ order: { orderId: "o3", negotiationId: "n3" }, deliverThrows: true });
  const h = createScanHandler(client, cfg(scan));
  h.pending.set("o3", "https://victim.example");
  await h.handlePaidOrder("o3");

  assert.equal(calls.deliver, 3, "delivery retried 3 times");
  assert.ok(!h.handledOrders.has("o3"), "un-marked so reconcile/replay can retry");
  assert.ok(h.pending.has("o3"), "target kept for the retry");

  await h.handlePaidOrder("o3"); // retry
  assert.equal(seen.length, 2, "retry re-scans (no money spent, so a fresh scan is fine)");
}

// ── 4. Already delivered: a post-restart replay must not re-scan / re-deliver ─
{
  const { scan, seen } = makeScan();
  const { client, calls } = makeClient({ order: { orderId: "o4", negotiationId: "n4", deliveredAt: "2026-01-01" } });
  const h = createScanHandler(client, cfg(scan));
  h.pending.set("o4", "https://victim.example");
  await h.handlePaidOrder("o4");

  assert.equal(seen.length, 0, "no scan on an already-delivered order");
  assert.equal(calls.deliver, 0, "no re-delivery");
}

// ── 5. Recovery: no pending entry -> target recovered from the negotiation ────
{
  const { scan, seen } = makeScan();
  const { client, calls } = makeClient({
    order: { orderId: "o5", negotiationId: "n5" },
    negotiation: { requirements: JSON.stringify({ target_url: "https://recovered.example" }) },
  });
  const h = createScanHandler(client, cfg(scan));
  await h.handlePaidOrder("o5"); // pending is empty -> must recover via getNegotiation

  assert.equal(calls.getNegotiation, 1, "recovered requirements from the negotiation");
  assert.deepEqual(seen, ["https://recovered.example"], "scanned the recovered target");
  assert.equal(calls.deliver, 1, "delivered the recovered scan");
}

// ── 6. No target after recovery: un-mark, deliver nothing ────────────────────
{
  const { scan, seen } = makeScan();
  const { client, calls } = makeClient({
    order: { orderId: "o6", negotiationId: "n6" },
    negotiation: { requirements: "{}" }, // no target_url
  });
  const h = createScanHandler(client, cfg(scan));
  await h.handlePaidOrder("o6");

  assert.equal(seen.length, 0, "no scan without a target");
  assert.equal(calls.deliver, 0, "nothing delivered");
  assert.ok(!h.handledOrders.has("o6"), "un-marked so a later retry is possible if a target arrives");
}

// ── 7. getNegotiation throws pre-delivery: un-mark for retry ──────────────────
{
  const { scan } = makeScan();
  const { client } = makeClient({ order: { orderId: "o7", negotiationId: "n7" }, getNegotiationThrows: true });
  const h = createScanHandler(client, cfg(scan));
  await h.handlePaidOrder("o7");
  assert.ok(!h.handledOrders.has("o7"), "a pre-delivery throw un-marks the order so it can be retried");
}

// ── 8. Reconcile: sweep only paid-but-undelivered, process each once ──────────
{
  const { scan, seen } = makeScan();
  const { client, calls } = makeClient({
    listOrders: [
      { orderId: "r1", negotiationId: "n1", status: "paid" },
      { orderId: "r2", negotiationId: "n2", status: "completed" }, // not undelivered -> skip
      { orderId: "r3", negotiationId: "n3", status: "delivering", deliveredAt: "x" }, // already delivered -> skip
    ],
  });
  const h = createScanHandler(client, cfg(scan));
  await h.reconcile();

  assert.equal(seen.length, 1, "only the paid-but-undelivered order (r1) is scanned");
  assert.equal(calls.deliver, 1, "only r1 delivered");
}

console.log(
  "PASS  scan path: happy scan+deliver, idempotent replay, deliver-fail retry, deliveredAt guard, " +
    "negotiation recovery, no-target un-mark, pre-delivery-throw un-mark, reconcile status filter.",
);
