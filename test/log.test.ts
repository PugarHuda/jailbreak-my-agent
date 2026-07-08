import assert from "node:assert/strict";
import { _scrubForTest as scrub, installConsoleScrub } from "../src/log.js";

const url = "websocket connecting wss://api.croo.network/ws?key=croo_sk_FAKEtestKEY000000000000000000000";
assert.ok(!scrub(url).includes("croo_sk_FAKEtestKEY000000000000000000000"), "SDK key must be redacted");
assert.match(scrub(url), /key=REDACTED/);

// mid-query key redacted, surrounding params kept
const multi = scrub("https://x/y?foo=1&key=SECRETVAL&bar=2");
assert.ok(!multi.includes("SECRETVAL"), "key value must be gone");
assert.match(multi, /foo=1/);
assert.match(multi, /bar=2/);

// non-secret strings untouched
assert.equal(scrub("nothing to hide here"), "nothing to hide here");

// the key TOKEN is redacted anywhere, not just in a ?key= param (e.g. in a stack)
assert.ok(!scrub("Error at croo_sk_abcDEF123456 line 5").includes("croo_sk_abcDEF123456"), "bare key token redacted anywhere");

// installConsoleScrub: the app's own console.error(err) can't leak the key either
let captured = "";
const orig = console.error;
console.error = (...a: unknown[]) => {
  captured = a.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(" ");
};
installConsoleScrub(); // wraps the (captured) console.error with the scrubber
console.error("orderPaid handler error:", { url: "wss://api/ws?key=croo_sk_LIVEKEY9999" });
console.error = orig;
assert.ok(!captured.includes("croo_sk_LIVEKEY9999"), "installConsoleScrub redacts the key in app error logs");

console.log("PASS  log: key scrubbed from urls + bare tokens + app console.error, other params preserved.");
