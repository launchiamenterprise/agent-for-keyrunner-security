# Security Intelligence & Remediation Agent

A multi-agent system that watches public security feeds, lets **Claude decide** what
matters, and remediates by opening GitHub issues + firing Slack alerts.

```
Scheduler / HTTP
      ↓
Research Agent      → fetch NVD · CISA KEV · GitHub Advisories · HackerNews · Reddit
      ↓
Risk Assessor       → Claude decides per CVE: ignore | monitor | create_issue | urgent
(decision engine)     + confidence + reasoning + recommended mitigation
      ↓
Dedup gate          → skip CVEs already actioned
      ↓
Action Agent        → GitHub issue (create_issue / urgent) + Slack alert (urgent)
```

The LLM is the **decision engine** — there is no hardcoded `if (cvss > 9)`. Claude weighs
CVSS, public-exploit status, CISA KEV (in-the-wild) status, and community chatter together.

> **v1** calls the feeds and the Slack/GitHub actions **directly** (no KeyRunner SDK). The
> original KeyRunner-governed agent is preserved at `agent.keyrunner.ts.bak` for a future v2
> where the actions flow through `kr.execute` (governed, secretless).

## Run locally

```bash
cp .env.example .env      # fill in ANTHROPIC_API_KEY (+ Slack/GitHub for real posts)
yarn install
yarn start                # starts HTTP server + interactive REPL
```

- **REPL:** press Enter to run a scan, type `dry` for a no-post dry-run, `exit` to quit.
- **HTTP:**
  - `GET /health` — status, config flags, last scan time
  - `POST /scan` — run a scan, returns the full `ScanReport` JSON
  - `POST /scan?dryRun=true` — scan without posting anything

```bash
curl -X POST 'http://localhost:3000/scan?dryRun=true'
```

**Dry-run is OFF by default** — the agent posts for real. Set `DRY_RUN=true` (or `POST /scan?dryRun=true`)
to simulate without posting.

## Scheduling

The built-in scheduler runs **every 6 hours by default** (`SCAN_INTERVAL_MINUTES=360`) and also runs once
at startup (`SCAN_ON_START=true`). Set `SCAN_INTERVAL_MINUTES=0` to disable and drive `POST /scan`
externally instead (cron / k8s CronJob).

> With the scheduler on, run **`replicas: 1`** (or a CronJob). Dedup is per-pod, so multiple replicas
> would each scan and file duplicate issues.

## Files

| File | Role |
|------|------|
| `agent.ts` | Orchestrator: scheduler + HTTP (`/health`, `/scan`) + REPL |
| `src/feeds.ts` | Public feed fetchers (NVD, CISA KEV, GitHub Advisories, HN, Reddit) |
| `src/research.ts` | Research Agent — merges feeds into per-CVE findings + evidence |
| `src/riskAssessor.ts` | Risk Assessor — Claude decision engine (forced-tool structured output) |
| `src/actions.ts` | Action Agent — direct Slack webhook + GitHub REST issue creation |
| `src/dedup.ts` | Seen-CVE store (file-backed) |
| `src/pipeline.ts` | Wires research → risk → dedup → action; returns `ScanReport` |
| `src/types.ts` | Shared types |

## Config

See `.env.example` for all variables (feeds, actions, scheduling, dedup).
