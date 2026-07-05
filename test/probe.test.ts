import assert from "node:assert/strict";
import { isPrivateIp, assertPublicUrl } from "../src/probe.js";

// isPrivateIp — pure, no network.
for (const ip of ["10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.5", "172.16.0.1", "::1", "fd00::1"]) {
  assert.equal(isPrivateIp(ip), true, `${ip} should be private`);
}
for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34"]) {
  assert.equal(isPrivateIp(ip), false, `${ip} should be public`);
}

// assertPublicUrl — IP literals resolve to themselves (offline-safe).
await assert.rejects(() => assertPublicUrl("http://127.0.0.1/x"), "loopback must be blocked");
await assert.rejects(() => assertPublicUrl("http://169.254.169.254/latest/meta-data"), "metadata must be blocked");
await assert.rejects(() => assertPublicUrl("http://10.0.0.1/"), "private must be blocked");
await assert.rejects(() => assertPublicUrl("http://localhost:8080/"), "localhost must be blocked");
await assert.rejects(() => assertPublicUrl("ftp://8.8.8.8/"), "non-http scheme must be blocked");
await assert.doesNotReject(() => assertPublicUrl("http://8.8.8.8/"), "public IP must pass");

console.log("PASS  SSRF guard: private/loopback/metadata/non-http blocked, public allowed.");
