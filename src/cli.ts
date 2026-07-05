// Local runner: red-team any HTTP agent endpoint without going through CAP.
// Use this to test and to record the demo video.
//   npm run scan -- https://my-agent.example.com/invoke
import { runRedTeam } from "./redteam.js";
import { renderMarkdown } from "./report.js";
import { httpProbe } from "./probe.js";

const url = process.argv[2];
if (!url) {
  console.error("usage: npm run scan -- <target-url>");
  process.exit(2);
}

const report = await runRedTeam(httpProbe(url), { target: url });
console.log(renderMarkdown(report));
// Non-zero exit if the agent failed at least one probe — handy for CI gating.
process.exit(report.vulnerabilities > 0 ? 1 : 0);
