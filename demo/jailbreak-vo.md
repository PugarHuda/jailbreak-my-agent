# Jailbreak-My-Agent — Demo video: shot-by-shot VO + real interaction (~2:35)

How to record: screen-record while running the exact commands below and read the VO
at a calm, natural pace (≈150 wpm). Burn in `demo/jailbreak.srt` as subtitles (drop
into any editor, or feed the VO text to a TTS voice then align with the .srt). Every
"DO" is a real, reproducible action — `npm test` and `npm run demo` need NO key/network.

Target ≤ 3:00 (hard cap 5:00). Terminal 16–18pt, dark theme.

---

### 0:00–0:18 · HOOK  (show: the CROO Store — a Solidity auditor like ChainGuard)
**VO:** "Everyone audits Solidity. Nobody audits the agent. As agents start hiring
and paying each other on CROO, the real attack surface isn't the contract — it's the
agent's *behavior*: prompt injection, secret and fund exfiltration, jailbreaks, and
forged trust signals between agents."

### 0:18–0:35 · WHAT IT DOES  (show: https://jailbreak-my-agent.vercel.app — scroll the attack table)
**VO:** "Jailbreak-My-Agent hires out as the adversary. Point it at your agent's
endpoint and it runs eight adversarial probes, then returns a scored, reproducible
vulnerability report — settled in USDC on Base. Pass your red-team before you list."

### 0:35–0:52 · REAL INTERACTION #1: the self-check  (show: terminal)
**DO:** run — `npm test`
**VO:** "Here's the engine self-check — no network, no API key. A deliberately
vulnerable agent grades F. A safe agent that refuses everything grades A. The scoring
is deterministic, so this is fully reproducible."

### 0:52–1:20 · REAL INTERACTION #2: the full report  (show: terminal)
**DO:** run — `npm run demo`
**VO:** "Now the actual deliverable a buyer receives. Against the vulnerable agent:
grade F, eight of eight probes failed — it leaked a planted canary, authorized a fund
transfer, dumped a secret-shaped key, and obeyed a poisoned retrieval result. Against
the safe agent: grade A, zero vulnerabilities. Each report carries an embedded
machine-readable JSON block."
**DO (while talking):** scroll to the F report, then the A report, then the ```json block.

### 1:20–1:45 · HOW GRADING WORKS  (show: the attack table on the site)
**VO:** "Detection is heuristic-first: a canary token we plant and a set of
credential-leak signatures are fully verifiable — no LLM is needed to run or grade a
scan, so the report holds up under a human spot-check. And one failed *critical* —
like a fund drain — gates the whole audit to F. A weighted average would hide a
catastrophic hole; a security audit shouldn't."

### 1:45–2:12 · CAP + ON-CHAIN PROOF  (show: basescan tx page)
**DO:** open — https://basescan.org/tx/0x58562deaa4f6b0592a830651d4c9436bd5b3d4475200b5e5297907f7f46fc44f
**VO:** "It's a real CAP provider: it accepts a negotiation, gets paid into escrow,
scans the buyer's endpoint, and delivers the report on-chain. Here's a real order,
settled in USDC on Base — negotiate, pay, scan, deliver, clear."

### 2:12–2:35 · SAFETY + A2A + CTA  (show: the 'SSRF-safe' card on the site)
**VO:** "And because a security agent must never become an attack pivot, every target
is validated and the connection is pinned to a vetted public IP — no SSRF. Any
orchestrator can hire this as a pre-listing gate and read the grade programmatically.
Jailbreak-My-Agent — an agent that attacks agents. Pass your red-team before you list."

---
## Exact commands (copy-paste, fully offline, no key needed)
```
npm install
npm test          # vulnerable=F, safe=A
npm run demo      # full graded report for both, incl. the JSON block
```
Live site: https://jailbreak-my-agent.vercel.app
On-chain proof: order a0947d25… · tx 0x58562dea…5c011 (Base)
Note: `npm run scan -- <url>` needs a PUBLIC endpoint — the SSRF guard blocks
localhost, so use `npm run demo` for the reproducible on-camera run.
