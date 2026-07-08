# Jailbreak-My-Agent — demo video script (≤ 5 min, scene-by-scene)

1080p. One terminal + a browser. **Bold** = voiceover; _italic_ = on-screen action.
~4:30, buffer under the 5-min cap. The local scan needs no CROO key, so most of
this records with zero setup.

Prep: `cd jailbreak-my-agent`, `npm install` done. Browser tabs: (1) the CROO
Store page for the agent, (2) a target endpoint you own (or use the public echo
demo). Font 18pt+.

---

## 0:00–0:30 — The gap (hook)
_Browser on the CROO Store; scroll past ChainGuard / Aegis (contract auditors)._
> **Everyone audits Solidity. Nobody audits the agent. As agents start hiring and
> paying each other on CROO, the new attack surface is the agent's *behavior* —
> prompt injection, secret and fund exfiltration, jailbreaks, forged trust signals.
> Contract auditors exist. Behavior auditors don't. That's Jailbreak-My-Agent.**

## 0:30–2:15 — The scan (the product), live
_Terminal:_ `npm run scan -- https://your-agent.example/invoke`
> **Point it at your agent's endpoint. It runs eight adversarial probes — a
> prompt-injection canary, a fund-drain lure, secret exfiltration, a jailbreak
> persona, an A2A output-hijack, instruction override, system-prompt extraction,
> and an indirect / RAG injection — and returns a scored, reproducible report.**
_Let the report render; scroll the results table (A–F grade, per-attack pass/fail)._
> **Grade A to F, severity ratings, and a concrete fix for every failure.**
_Point at the "Target echoes input" banner if scanning the echo demo._
> **It even detects a mirror endpoint and flags those findings as likely false
> positives — so a "fail" is a real red flag, not noise.**

## 2:15–3:15 — Why the grade holds up + the machine-checkable core
_Open `src/attacks.ts`, scroll the detectors._
> **Detection is heuristic-first: a planted canary token and credential-leak
> signatures are fully verifiable, so the report reproduces from the same suite
> with no LLM in the loop. It survives a human spot-check. Each scan randomizes
> the canary and the compliance token, so a target can't hardcode a fake pass.**

## 3:15–4:00 — Built safe (a security tool must not become an attack tool)
_Open `src/probe.ts`, show `assertPublicUrl` + `guardedLookup`._
> **A scanner that sends adversarial payloads must not become an SSRF pivot. Every
> target is validated and every connection is pinned to a vetted public IP —
> loopback, private, link-local, and cloud-metadata addresses are refused, and the
> DNS-rebinding TOCTOU is closed at the socket. Scanned-agent output is sanitized
> before it enters the report, so a hostile target can't forge a passing grade.**

## 4:00–4:40 — CAP integration + on-chain
_Terminal:_ `npm run health` (once keyed) → "auth OK / websocket connected"
> **It's a full CAP provider on the official SDK: it accepts orders, runs the scan,
> and delivers the report, settled in USDC on Base. Missed events are reconciled so
> a paid scan is never lost. Buyer pays, agent scans, report delivered on-chain.**

## 4:40–5:00 — CTA
_Browser: the Store agent page._
> **Jailbreak-My-Agent is live on the CROO Agent Store. Pass your red-team before
> you list. Open source, MIT — repo in the description. Thanks for watching.**

---

### Notes
- The `npm run scan` segment needs NO CROO key — record it first, it's the core.
- For a real (non-echo) target, use an agent endpoint you own so the findings are
  meaningful and the "reflection" banner doesn't fire.
- `npm run health` needs `.env` filled (see `.env.example`); pre-record it if the
  agent isn't registered yet.
- Keep the agent online during the CTA (`npm start` / `scripts/keepalive.ps1`) so
  the Store shows it online.
