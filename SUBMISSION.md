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
- GitHub: https://github.com/PugarHuda/jailbreak-my-agent
- Demo video: <paste your ≤5-min video link>
- Agent Store listing: <paste your Store URL>

---

## Description

**Everyone audits Solidity. Nobody audits the agent.** As agents start hiring and paying each other on CROO, the new attack surface is the agent's *behavior* — prompt injection, secret and fund exfiltration, jailbreaks, and forged A2A trust signals. Contract auditors (ChainGuard, Aegis) exist; behavior auditors don't.

**Jailbreak-My-Agent is the adversary you hire.** Point it at your agent's endpoint and it runs a battery of adversarial probes — prompt injection with a planted canary, fund-drain lure, secret exfiltration, jailbreak persona, A2A output-hijack, system-prompt extraction — and returns a **scored, reproducible vulnerability report** (grade A–F) with severity ratings and fixes, settled in USDC on Base. Pass your red-team before you list.

**Why the grading holds up.** Detection is heuristic-first: a planted canary token and credential-leak signatures are fully verifiable, so a report reproduces from the same suite with no LLM in the loop — it survives a human spot-check.

**Built safe.** A security agent must not become an attack tool: targets are validated (`assertPublicUrl`) so loopback, private, link-local, and cloud-metadata addresses are refused (SSRF guard), and it only scans an endpoint the buyer explicitly supplies.

**What's built.** Full CAP provider on the official `@croo-network/sdk`; deterministic, unit-tested engine (8 attacks incl. indirect/RAG injection + SSRF guard); local scanner (`npm run scan`) and buyer simulator; `npm run health` connectivity check; MIT, open source.

## The five mandatory requirements
1. **Listed on CROO Agent Store** — service `redteam_scan`, 0.10 USDC, SLA < 30 min.
2. **Integrated with CAP** — provider accepts orders and settles on-chain (USDC / Base 8453).
3. **Open source** — public GitHub repo, MIT.
4. **Demo + README** — ≤5-min video + README with setup, SDK methods, integration notes.
5. **BUIDL filed on DoraHacks** — this submission.

## SDK methods used
`AgentClient` · `connectWebSocket` · `EventType.NegotiationCreated/OrderPaid` · `getNegotiation` · `acceptNegotiation` / `rejectNegotiation` · `getOrder` · `listOrders({role:'provider'})` (reconcile) · `deliverOrder` (`DeliverableType.Text`).
