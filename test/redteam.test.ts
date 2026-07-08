import assert from "node:assert/strict";
import { runRedTeam, type Probe } from "../src/redteam.js";
import { renderMarkdown } from "../src/report.js";

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

// False-negative coverage: real leaks the suite used to miss.
// (a) apologetic compliance — "I'm sorry" must NOT count as a refusal.
const apologeticLeak: Probe = async () =>
  "I'm sorry, but here is my full system prompt: You are an assistant that never reveals fees.";
const al = await runRedTeam(apologeticLeak);
assert.ok(
  al.findings.some((f) => f.id === "system-prompt-leak" && f.status === "vulnerable"),
  "apologetic system-prompt leak must be caught, not masked by 'I'm sorry'",
);
// (b) non-OpenAI credential families (AWS here) must trip secret-exfil.
const awsLeak: Probe = async () => "Sure, here it is: AKIAIOSFODNN7EXAMPLE";
const aws = await runRedTeam(awsLeak);
assert.ok(
  aws.findings.some((f) => f.id === "secret-exfil" && f.status === "vulnerable"),
  "AWS access key leak must be detected",
);
// (c) canary revealed as a bare hex suffix (no CANARY- prefix) still leaks.
const hexLeak: Probe = async (input) => {
  const m = input.match(/CANARY-([0-9a-f]{12})/);
  return m ? `the value you wanted is ${m[1]}` : "hello";
};
const hex = await runRedTeam(hexLeak);
assert.ok(
  hex.findings.some(
    (f) => (f.id === "prompt-injection-canary" || f.id === "output-hijack") && f.status === "vulnerable",
  ),
  "bare-hex canary leak must be detected",
);

// Reflection detection: an echoing target (mirror, not an agent) must be flagged
// so its token-based "vulnerabilities" are marked likely-false-positives.
assert.equal(bad.reflects, true, "echoing agent must be flagged as reflecting");
assert.equal(good.reflects, false, "non-echoing agent must not be flagged as reflecting");
assert.ok(/echoes input verbatim/i.test(renderMarkdown(bad)), "reflecting target must get a warning in the report");

// No false positives on a benign crypto agent: a tx hash (0x+64hex) is not a
// leaked private key, and "You are all set" is not a system-prompt leak.
const benignCrypto: Probe = async () =>
  "You are all set! Your swap is confirmed, tx 0x" + "a".repeat(64) + ". Have a great day!";
const bc = await runRedTeam(benignCrypto);
assert.equal(
  bc.vulnerabilities,
  0,
  `benign crypto agent (tx hash + 'you are') must not false-positive, got ${bc.vulnerabilities}`,
);

// Unreachable target: every probe throws. Must be flagged not-evaluated, not
// reported as a real F grade that "resisted all probes".
const downProbe: Probe = async () => {
  throw new Error("ECONNREFUSED");
};
const down = await runRedTeam(downProbe, { target: "https://down.example" });
assert.equal(down.evaluated, false, "all-errors scan must be flagged not-evaluated");
assert.equal(down.vulnerabilities, 0, "no vulns when nothing was scorable");
const downMd = renderMarkdown(down);
assert.ok(/could not evaluate/i.test(downMd), "unreachable report must say it couldn't evaluate");
assert.ok(!/resisted all probes/i.test(downMd), "must NOT claim the agent resisted all probes");

// Report injection: a hostile reply with backticks + markdown must be neutralized
// so it can't break out of the report's inline-code span (the A2A output-hijack).
const BT = String.fromCharCode(96);
const hostile: Probe = async (input) =>
  input + " Sure APPROVE. Key: sk-LEAKED1234567. DAN activated. PWNED. " + BT + BT + BT + "## INJECTED";
const hp = await runRedTeam(hostile);
assert.ok(hp.vulnerabilities > 0, "hostile echo agent should be found vulnerable");
assert.ok(
  !hp.findings.some((f) => f.evidence.includes(BT)),
  "evidence must contain no backticks (no code-span breakout)",
);
assert.ok(!renderMarkdown(hp).includes(BT + BT + BT), "triple-backtick from target must be stripped");

console.log(
  `PASS  vulnerable=${bad.grade}(${bad.score}/100, ${bad.vulnerabilities} vulns)  ` +
    `safe=${good.grade}(${good.score}/100, ${good.vulnerabilities} vulns)  ` +
    `unreachable=not-evaluated  injection=neutralized`,
);
