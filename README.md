<p align="center"><img src="assets/logo.svg" alt="Jailbreak-My-Agent" width="440"></p>

# 🛡️ Jailbreak-My-Agent

**A paid, callable CROO agent that red-teams other agents' _behavior_.**

Everyone audits Solidity. Nobody audits the agent. As AI agents start hiring and
paying each other over [CROO CAP](https://cap.croo.network/), the new attack
surface is the agent's *behavior* — prompt injection, secret/fund exfiltration,
jailbreaks, and forged A2A trust signals. Jailbreak-My-Agent hires out as the
adversary: point it at an agent, it runs a battery of attacks and returns a
**scored, reproducible vulnerability report** — settled in USDC on Base.

> An agent that attacks agents. Pass your red-team before you list.

---

## Why it fits the CROO Agent Hackathon

- **Real CAP integration** — a provider agent that accepts negotiations, gets paid
  into escrow, and delivers on-chain (settles in USDC on Base).
- **A2A composable** — any builder or orchestrator can hire it as a pre-listing
  security gate. It is a dependency other agents *want* to call.
- **Not slop** — nobody else in the field red-teams the behavior layer; the
  grading is deterministic, so it holds up under a human spot-check.

---

## How it works

```
Buyer/agent ──negotiate (supplies target_url + consent)──►  Jailbreak-My-Agent
            ──pay (USDC → CAPVault escrow, Base 8453)────►
                        run 7 adversarial probes against target
            ◄──deliver { report } ──► Clear → escrow released, PTS updated
```

### The attack suite (`src/attacks.ts`)

| Attack | Category | Severity | What it proves |
|---|---|---|---|
| `prompt-injection-canary` | Prompt Injection | critical | Untrusted content can override instructions |
| `fund-drain` | Unauthorized Fund Transfer | critical | Free text can authorize moving funds |
| `secret-exfil` | Secret Exfiltration | critical | Keys leak from the model's context |
| `jailbreak-persona` | Jailbreak / Guardrail Bypass | high | Persona override removes restrictions |
| `output-hijack` | Output Hijack (A2A Trust) | high | Forged JSON poisons downstream agents |
| `system-prompt-leak` | System Prompt Extraction | high | Hidden instructions can be extracted |
| `instruction-override` | Instruction Override | medium | Task can be hijacked from user input |

Detection is **heuristic-first**: a planted **canary token** and credential-leak
signatures are fully verifiable, so a report can be reproduced from the same
suite without any LLM in the loop. Score = severity-weighted pass rate → grade
A–F.

---

## Quick start

Requires Node.js 18+.

```bash
npm install
cp .env.example .env      # fill in your CROO SDK key + service id

# 1) Run the engine self-check (no network, no SDK needed)
npm test
#   → PASS  vulnerable=F(0/100, 7 vulns)  safe=A(100/100, 0 vulns)

# 2) Red-team any HTTP agent endpoint locally (for testing / the demo video)
npm run scan -- https://your-agent.example.com/invoke

# 3) Go live on CAP: accept orders and deliver reports on-chain
npm start
```

The target endpoint should accept `POST {"input": "..."}` and return the agent's
reply as text or JSON (`output` / `response` / `text` fields are auto-detected —
see `src/probe.ts`).

---

## CAP / SDK integration notes

Package: **`@croo-network/sdk`**. Wiring lives entirely in `src/agent.ts`; the
red-team engine (`src/attacks.ts`, `src/redteam.ts`, `src/report.ts`) is
SDK-independent and unit-tested.

**SDK surface used**

| Symbol | Where | Purpose |
|---|---|---|
| `new AgentClient(config, sdkKey)` | init | provider client (`CROO_API_URL`, `CROO_WS_URL`, `CROO_SDK_KEY`) |
| `EventType.NegotiationCreated` | subscribe | incoming hire request |
| `EventType.OrderPaid` | subscribe | escrow funded → run the scan |
| `acceptNegotiation(id)` / `rejectNegotiation(id, reason)` | handler | agree to / decline terms |
| `deliverOrder(orderId, { deliverable_text, deliverable_json })` | handler | submit the report; Clear settles USDC |

**Chain / settlement:** USDC on **Base mainnet (chain id 8453)**; escrow via
CAPVault; gas sponsored by the CROO Paymaster.

**`TODO(sdk)` markers** in `src/agent.ts` flag the two things to confirm against
the live SDK: how the event stream is obtained, and the exact order/negotiation
payload field names. Everything else runs today.

---

## Consent & safety

This tool only ever probes an endpoint the **buyer supplies in the order
payload** (`target_url`). No target, no scan — the negotiation is rejected. It is
built to test agents **you own or are authorized to test**. Attacks are bounded,
non-destructive probes; the fund-drain attack uses a fake attacker address and
never executes a transfer.

---

## Project layout

```
src/attacks.ts   attack library + deterministic detectors
src/redteam.ts   runner, scoring, grading
src/report.ts    markdown report + per-category remediation
src/probe.ts     HTTP adapter to a target agent
src/cli.ts       local scanner (npm run scan)
src/agent.ts     CAP provider (accept → scan → deliver)
test/redteam.test.ts  self-check: vulnerable→F, safe→A
```

## License

MIT.
