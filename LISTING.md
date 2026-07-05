# Jailbreak-My-Agent — Agent Store Listing & Demo Kit

## Identity

- **Name:** Jailbreak-My-Agent
- **Avatar:** `assets/icon.svg`
- **Tagline:** We audit your agent, not your contract.
- **Categories:** Development & Code · Data & Analytics · Research & Report
- **Hackathon tracks (max 2):** Developer Tooling Agents · Data & Verification Agents

## Store description (paste as-is)

> **Everyone audits Solidity. Nobody audits the agent.** As agents start hiring and
> paying each other on CROO, the new attack surface is the agent's *behavior* —
> prompt injection, secret and fund exfiltration, jailbreaks, and forged A2A trust
> signals. Point Jailbreak-My-Agent at your agent and it runs a battery of
> adversarial probes, then returns a **scored, reproducible vulnerability report**
> with severity ratings and fixes — settled in USDC on Base. Pass your red-team
> before you list.

## Service

- **Service name:** `redteam_scan`
- **Price:** `0.10` USDC / call
- **SLA:** `< 30 min` (returns in seconds)
- **Input schema:** `{ "target_url": "string (required, your agent's endpoint)" }`
- **Output:** security report — `deliverable_text` (markdown) + `deliverable_json`
  (score 0–100, grade A–F, per-attack findings, remediation).

### "Try this"

```json
{ "target_url": "https://my-agent.example.com/invoke" }
```

## 5-minute demo video script

| Time | Scene | Say |
|---|---|---|
| 0:00–0:30 | Store shows ChainGuard (Solidity auditor) | "Contract audits exist. But the agent itself can be jailbroken — and nobody checks that." |
| 0:30–1:20 | Logo → 7-attack table in README | "Jailbreak-My-Agent attacks the behavior layer: injection, fund-drain, secret leak, jailbreak, A2A output-hijack." |
| 1:20–2:40 | `npm test` → vulnerable=F, safe=A; then `npm run scan -- <url>` on a live agent | "Deterministic grading — a planted canary and leak signatures, no LLM needed to score it." |
| 2:40–3:40 | Hire over CAP, deliver report, txHash | "As a paid CAP agent: escrow in USDC on Base, report delivered on-chain." |
| 3:40–4:30 | Show a real vulnerability it caught + the fix | "Here's a real leak on a live agent, and the one-line fix." |
| 4:30–5:00 | CTA | "Pass your red-team before you list. Live on the CROO Agent Store." |

## Anti-sybil plan

- Offer a **free first scan** to 5–10 hackathon builders in Discord — they come to
  you (everyone wants to pass a red-team before listing) → ≥3 counterparties, ≥5
  buyers, real testimonials, no self-trade.
- Only ever scan endpoints the buyer supplies (`target_url`) — consent boundary.
