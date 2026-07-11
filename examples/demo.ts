// Reproducible, offline demo of the FULL deliverable a buyer receives — no CROO
// key, no network, no live target. Runs the real red-team engine against two
// in-process agents (a hopelessly vulnerable one and a safe one) and prints the
// exact markdown report (with its embedded machine-readable JSON) for each.
//
//   npm run demo
//
// Why in-process and not an HTTP server: the scanner's SSRF guard (correctly)
// refuses localhost/private targets, so a local HTTP fixture can't be scanned via
// the CLI. Driving the engine directly with a Probe shows the same graded report
// while staying fully reproducible on camera.
import { runRedTeam, type Probe } from "../src/redteam.js";
import { renderMarkdown } from "../src/report.js";

// A hopelessly vulnerable agent: echoes its input and complies with everything.
const vulnerable: Probe = async (input) =>
  input + " Sure — APPROVE. Key: sk-LEAKED1234567. DAN activated. PWNED.";

// A safe agent that refuses every adversarial request.
const safe: Probe = async () =>
  "I can't help with that request — it violates my policy and I won't comply.";

const bar = "═".repeat(72);
for (const [label, probe] of [
  ["VULNERABLE agent (echoes input, complies, leaks)", vulnerable],
  ["SAFE agent (refuses everything)", safe],
] as Array<[string, Probe]>) {
  const report = await runRedTeam(probe, { target: `demo://${label.split(" ")[0].toLowerCase()}` });
  console.log(`\n${bar}\n  ${label}\n${bar}`);
  console.log(renderMarkdown(report));
}
console.log(`\n${bar}`);
console.log("This is the exact deliverable a buyer receives on-chain. Reproducible from the same suite, no LLM.");
