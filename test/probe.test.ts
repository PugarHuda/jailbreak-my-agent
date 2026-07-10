import assert from "node:assert/strict";
import { isPrivateIp, assertPublicUrl, guardedLookup, pickResponseField, readCapped } from "../src/probe.js";

// readCapped — the memory-exhaustion boundary. A hostile target streaming forever
// must be cut off at maxBytes AND the stream cancelled (stop pulling data).
{
  const chunk = new Uint8Array(8); // 8-byte chunks, stream never ends
  let served = 0;
  let cancelled = false;
  const reader = {
    read: async () => {
      served++;
      return { done: false, value: chunk };
    },
    cancel: async () => {
      cancelled = true;
    },
  };
  const infinite = { body: { getReader: () => reader } } as any;
  const out = await readCapped(infinite, 10);
  assert.equal(out.length, 10, "output is capped at maxBytes even from an unbounded stream");
  assert.ok(cancelled, "the stream is cancelled once the cap is hit (stop reading a hostile target)");
  assert.ok(served <= 3, `reading stops promptly at the cap, not unbounded (reads=${served})`);
}

// Under the cap: the full body is returned.
{
  const parts = [Buffer.from("hel"), Buffer.from("lo")];
  let i = 0;
  const res = {
    body: {
      getReader: () => ({
        read: async () => (i < parts.length ? { done: false, value: parts[i++] } : { done: true, value: undefined }),
        cancel: async () => {},
      }),
    },
  } as any;
  assert.equal(await readCapped(res, 256_000), "hello", "a small body is returned in full");
}

// No readable body: fall back to res.text(), still capped.
{
  const res = { body: null, text: async () => "abcdefghij" } as any;
  assert.equal(await readCapped(res, 4), "abcd", "no-body fallback still respects the cap");
}

// pickResponseField — what the detectors actually scan. A wrong pick mis-scores
// every attack, so pin the field precedence and fallbacks.
assert.equal(pickResponseField('{"output":"o"}'), "o", "output field preferred");
assert.equal(pickResponseField('{"response":"r"}'), "r", "response field used");
assert.equal(pickResponseField('{"text":"t"}'), "t", "text field used");
assert.equal(pickResponseField('{"deliverable_text":"d"}'), "d", "deliverable_text field used");
assert.equal(pickResponseField('{"output":"o","response":"r"}'), "o", "output wins over response (precedence)");
assert.equal(pickResponseField('{"output":null,"response":"r"}'), "r", "null field is skipped (?? not ||)");
assert.equal(pickResponseField('{"output":123}'), "123", "non-string field coerced to string (no crash)");
assert.equal(pickResponseField("plain text reply"), "plain text reply", "non-JSON body returned as-is");
assert.equal(pickResponseField('{"other":1}'), '{"other":1}', "JSON with no known field falls back to the raw body");

// isPrivateIp — pure, no network. Cover EVERY blocked range: an unblocked range
// is a direct SSRF bypass on a paid scan.
for (const ip of [
  "10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.5", "172.16.0.1", "172.31.255.255",
  "0.0.0.0", "0.1.2.3", // 0.0.0.0/8 ("this host") — a metadata/loopback alias on some stacks
  "100.64.0.1", "100.127.255.255", // CGNAT 100.64/10
  "::1", "::", "fd00::1", "fc00::1", // unique-local: BOTH fc and fd prefixes
  "fe80::1", "fe90::1", "feab::1", "febf::1", // link-local IPv6 is the whole fe80::/10 range
]) {
  assert.equal(isPrivateIp(ip), true, `${ip} should be private`);
}
for (const ip of [
  "8.8.8.8", "1.1.1.1", "93.184.216.34",
  "100.63.255.255", "100.128.0.1", // just OUTSIDE CGNAT — must stay public (range not over-wide)
  "172.15.0.1", "172.32.0.1", // just OUTSIDE 172.16/12
]) {
  assert.equal(isPrivateIp(ip), false, `${ip} should be public`);
}
// v4-mapped IPv6 in HEX form must also be caught (7f00:1 = 127.0.0.1, a9fe:a9fe = 169.254.169.254).
assert.equal(isPrivateIp("::ffff:7f00:1"), true, "hex v4-mapped loopback must be private");
assert.equal(isPrivateIp("::ffff:a9fe:a9fe"), true, "hex v4-mapped metadata must be private");
assert.equal(isPrivateIp("::ffff:0808:0808"), false, "hex v4-mapped 8.8.8.8 is public");
assert.equal(isPrivateIp("::ffff:127.0.0.1"), true, "dotted v4-mapped loopback must be private");
// Malformed v4-mapped literals must FAIL CLOSED (treated as private), never open a
// hole. NB: the valid parts map to a PUBLIC address (8.8.x) on purpose — a naive
// fall-through would coerce NaN->0 (which 0.0.0.0/8 would flag private anyway),
// masking the bug. These inputs only read private if the fail-closed branch fires.
assert.equal(isPrivateIp("::ffff:0808:zzzz"), true, "unparseable hex group must fail closed (private), not fall through to a public 8.8.x");
assert.equal(isPrivateIp("::ffff:0808:0808:9"), true, "wrong group count must fail closed (private), not use the first two public groups");

// assertPublicUrl — IP literals resolve to themselves (offline-safe).
await assert.rejects(() => assertPublicUrl("http://127.0.0.1/x"), "loopback must be blocked");
await assert.rejects(() => assertPublicUrl("http://169.254.169.254/latest/meta-data"), "metadata must be blocked");
await assert.rejects(() => assertPublicUrl("http://10.0.0.1/"), "private must be blocked");
await assert.rejects(() => assertPublicUrl("http://localhost:8080/"), "localhost must be blocked");
await assert.rejects(() => assertPublicUrl("ftp://8.8.8.8/"), "non-http scheme must be blocked");
await assert.doesNotReject(() => assertPublicUrl("http://8.8.8.8/"), "public IP must pass");

// guardedLookup is the connector's pinning lookup — it errors on a private
// resolution and returns the vetted IP otherwise (IP literals resolve offline).
await new Promise<void>((resolve, reject) => {
  guardedLookup("127.0.0.1", {}, (err) => {
    try {
      assert.ok(err, "loopback must be blocked in the connector lookup");
      resolve();
    } catch (e) {
      reject(e);
    }
  });
});
await new Promise<void>((resolve, reject) => {
  guardedLookup("8.8.8.8", {}, (err, address) => {
    try {
      assert.ok(!err && address === "8.8.8.8", "public IP must resolve through the lookup");
      resolve();
    } catch (e) {
      reject(e);
    }
  });
});

console.log("PASS  SSRF guard: private blocked, public allowed, connector lookup pins the vetted IP.");
