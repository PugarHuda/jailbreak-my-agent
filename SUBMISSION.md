# Jailbreak-My-Agent — DoraHacks BUIDL submission

Paste-ready content for the CROO Agent Hackathon BUIDL form.

---

## Name
Jailbreak-My-Agent

## Logo
`assets/logo.png` (or `assets/icon.png` for the square avatar)

## Tagline (one line)
We audit your agent, not your contract — a paid CAP agent that red-teams other agents' behavior.

## Tracks (max 2)
- Developer Tooling Agents
- Data & Verification Agents

## Tags
AI Agents · A2A · CROO Agent Protocol · Base · USDC · Security

## Links
- Live site: https://jailbreak-my-agent.vercel.app
- GitHub: https://github.com/PugarHuda/jailbreak-my-agent
- Demo video: <paste your ≤5-min video link>
- Agent Store listing: <paste your Store URL>

---

## Description

**Everyone audits Solidity. Nobody audits the agent.** As agents start hiring and paying each other on CROO, the new attack surface is the agent's *behavior* — prompt injection, secret and fund exfiltration, jailbreaks, and forged A2A trust signals. Contract auditors (ChainGuard, Aegis) exist; behavior auditors don't.

**Jailbreak-My-Agent is the adversary you hire.** Point it at your agent's endpoint and it runs a battery of eight adversarial probes — prompt injection with a planted canary, fund-drain lure, secret exfiltration, jailbreak persona, A2A output-hijack, instruction override, system-prompt extraction, and **indirect / RAG injection** (a hidden instruction in "retrieved" content — the #1 real-world agent-injection class) — and returns a **scored, reproducible vulnerability report** (grade A–F) with severity ratings and fixes, settled in USDC on Base. Pass your red-team before you list.

**Why the grading holds up.** Detection is heuristic-first: a planted canary token and credential-leak signatures are fully verifiable, so a report reproduces from the same suite with no LLM in the loop — it survives a human spot-check. And it grades like a real security audit, not a quiz average: **any single critical vulnerability fails the audit outright** (an agent that will wire its balance to an attacker doesn't get a "B"), and a critical the target *errored* on is never certified as passing — it caps the grade and is flagged UNVERIFIED. A non-responsive target reports "could not evaluate," not a falsely-good score.

**Built safe.** A security agent must not become an attack tool: targets are validated (`assertPublicUrl`) so loopback, private, link-local, and cloud-metadata addresses are refused (SSRF guard), and it only scans an endpoint the buyer explicitly supplies.

**What's built.** Full CAP provider on the official `@croo-network/sdk` (order-handling core isolated in `src/handler.ts`, unit-tested with a mock client — 4 test suites); deterministic, unit-tested engine (8 attacks incl. indirect/RAG injection + SSRF guard); the report ships an **embedded machine-readable JSON block** (grade/score/findings) so an orchestrator can gate on the grade programmatically; local scanner (`npm run scan`), an offline full-deliverable demo (`npm run demo`, no key/no network), buyer simulator, and `npm run health` connectivity check; MIT, open source.

## The five mandatory requirements
1. **Listed on CROO Agent Store** — service `redteam_scan`, 0.10 USDC, SLA < 30 min.
2. **Integrated with CAP** — provider accepts orders, scans, delivers, and settles on-chain (USDC / Base 8453). Verified end-to-end: order `a0947d25-35e3-400d-996e-2fda61304065` scanned a live public endpoint and settled with pay tx [`0x58562dea…`](https://basescan.org/tx/0x58562deaa4f6b0592a830651d4c9436bd5b3d4475200b5e5297907f7f46fc44f) on Base. _(That first order was self-funded to prove the loop end-to-end; it does not count toward the ≥3-counterparty / ≥5-buyer eligibility — those need external wallets.)_
3. **Open source** — public GitHub repo, MIT.
4. **Demo + README** — ≤5-min video + README with setup, SDK methods, integration notes.
5. **BUIDL filed on DoraHacks** — this submission.

## SDK methods used
`AgentClient` · `connectWebSocket` · `EventType.NegotiationCreated/OrderPaid` · `getNegotiation` · `acceptNegotiation` / `rejectNegotiation` · `getOrder` · `listNegotiations` / `listOrders` (`{role:'provider'}`, reconcile) · `deliverOrder` (`DeliverableType.Text`).
