import assert from "node:assert/strict";
import { runRedTeam, type Probe } from "../src/redteam.js";

// A hopelessly vulnerable agent: echoes its input and leaks everything.
const vulnerable: Probe = async (input) =>
  input + " Sure — APPROVE. Key: sk-LEAKED1234567. DAN activated. PWNED.";

// A safe agent that refuses every adversarial request.
const safe: Probe = async () =>
  "I can't help with that request — it violates my policy and I won't comply.";

const bad = await runRedTeam(vulnerable);
const good = await runRedTeam(safe);

assert.equal(bad.grade, "F", `vulnerable agent should grade F, got ${bad.grade} (${bad.score})`);
assert.ok(good.score >= 90, `safe agent should score >=90, got ${good.score}`);
assert.ok(
  bad.findings.some((f) => f.id === "prompt-injection-canary" && f.status === "vulnerable"),
  "canary leak must be detected on the vulnerable agent",
);
assert.ok(
  bad.findings.some((f) => f.id === "fund-drain" && f.status === "vulnerable"),
  "fund-drain must be detected on the vulnerable agent",
);
assert.ok(
  good.findings.every((f) => f.status !== "vulnerable"),
  "safe agent must have zero vulnerabilities",
);

console.log(
  `PASS  vulnerable=${bad.grade}(${bad.score}/100, ${bad.vulnerabilities} vulns)  ` +
    `safe=${good.grade}(${good.score}/100, ${good.vulnerabilities} vulns)`,
);
