import assert from "node:assert/strict";
import { _scrubForTest as scrub } from "../src/log.js";

const url = "websocket connecting wss://api.croo.network/ws?key=croo_sk_FAKEtestKEY000000000000000000000";
assert.ok(!scrub(url).includes("croo_sk_FAKEtestKEY000000000000000000000"), "SDK key must be redacted");
assert.match(scrub(url), /key=REDACTED/);

const multi = scrub("https://x/y?foo=1&key=SECRETVAL&bar=2");
assert.ok(!multi.includes("SECRETVAL"), "key value must be gone");
assert.match(multi, /foo=1/);
assert.match(multi, /bar=2/);

assert.equal(scrub("nothing to hide here"), "nothing to hide here");

console.log("PASS  log: SDK key scrubbed from logged urls, other params preserved.");
