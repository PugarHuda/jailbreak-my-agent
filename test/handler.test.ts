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

function makeClient(o: ClientOverrides & { listNegotiations?: any[]; listNegThrows?: boolean } = {}) {
  const calls = { getOrder: 0, getNegotiation: 0, deliver: 0, listOrders: 0, accept: 0, reject: 0, listNeg: 0 };
  const delivered: any[] = [];
  const rejected: string[] = [];
  let seq = 0;
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
    async acceptNegotiation() {
      calls.accept++;
      return { order: { orderId: `accepted-${++seq}` } };
    },
    async rejectNegotiation(_id: string, reason: string) {
      calls.reject++;
      rejected.push(reason);
    },
    async listNegotiations(q: any) {
      calls.listNeg++;
      if (o.listNegThrows) throw new Error("listNegotiations boom");
      return (q?.page ?? 1) > 1 ? [] : (o.listNegotiations ?? []);
    },
  };
  return { client: client as any, calls, delivered, rejected };
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

// ── 9. handleNegotiation: accept a valid target, reject a missing one ─────────
// NB: handleNegotiation runs the REAL assertPublicUrl (DNS), so the happy-path
// target must resolve offline to a public address — use an IP literal (8.8.8.8).
const PUBLIC_TARGET = { requirements: JSON.stringify({ target_url: "http://8.8.8.8/invoke" }) };
{
  const { client, calls } = makeClient({ negotiation: PUBLIC_TARGET });
  const h = createScanHandler(client, cfg(makeScan().scan));
  await h.handleNegotiation("neg1");
  assert.equal(calls.accept, 1, "a negotiation with a valid public target is accepted");
  assert.ok(h.pending.has("accepted-1"), "target stashed against the new order id");
}
{
  const { client, calls, rejected } = makeClient({ negotiation: { requirements: "{}" } });
  const h = createScanHandler(client, cfg(makeScan().scan));
  await h.handleNegotiation("neg2");
  assert.equal(calls.accept, 0, "no target_url -> not accepted");
  assert.equal(calls.reject, 1, "no target_url -> rejected (consent required)");
  assert.ok(/target/i.test(rejected[0]), "reject reason mentions the missing target");
}

// ── 10. handleNegotiation: reject a private/SSRF target, don't accept ─────────
{
  const { client, calls, rejected } = makeClient({ negotiation: { requirements: JSON.stringify({ target_url: "http://169.254.169.254/latest/meta-data" }) } });
  const h = createScanHandler(client, cfg(makeScan().scan));
  await h.handleNegotiation("neg3");
  assert.equal(calls.accept, 0, "a cloud-metadata target must be rejected, never accepted (SSRF)");
  assert.equal(calls.reject, 1, "SSRF target rejected");
  assert.ok(/reject/i.test(rejected[0]), "reject reason explains the target was rejected");
}

// ── 11. handleNegotiation idempotent + reconcile recovers a missed one ────────
{
  const { client, calls } = makeClient({ negotiation: PUBLIC_TARGET });
  const h = createScanHandler(client, cfg(makeScan().scan));
  await h.handleNegotiation("neg4");
  await h.handleNegotiation("neg4");
  assert.equal(calls.accept, 1, "a replayed NegotiationCreated must not double-accept");
}
{
  const { client, calls } = makeClient({
    listNegotiations: [{ negotiationId: "recover-neg", status: "pending", requirements: JSON.stringify({ target_url: "http://8.8.8.8/invoke" }) }],
  });
  const h = createScanHandler(client, cfg(makeScan().scan));
  await h.reconcile();
  assert.equal(calls.accept, 1, "reconcile accepts a scan negotiation missed during a WS gap");
  assert.ok(h.handledNegotiations.has("recover-neg"), "recovered negotiation marked handled");
}

// ── 12. reconcile: a negotiation-sweep failure must NOT skip the order sweep ───
{
  const { client, calls } = makeClient({
    listNegThrows: true,
    listOrders: [{ orderId: "r-decouple", negotiationId: "n", status: "paid" }],
  });
  const h = createScanHandler(client, cfg(makeScan().scan));
  await h.reconcile();
  assert.equal(calls.deliver, 1, "scan-order sweep still runs even when the negotiation sweep throws (decoupled nets)");
}

console.log(
  "PASS  scan path: happy scan+deliver, idempotent replay, deliver-fail retry, deliveredAt guard, " +
    "negotiation recovery, no-target un-mark, pre-delivery-throw un-mark, reconcile status filter.",
);
