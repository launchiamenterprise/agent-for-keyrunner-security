// ---------------------------------------------------------------------------
// Security Intelligence & Remediation Agent — orchestrator / entry point.
//
//   Scheduler / HTTP  →  Research Agent  →  Risk Assessor (Claude)
//                        →  Dedup gate    →  Action Agent (Slack + GitHub)
//
// v1: feeds + actions are called DIRECTLY (no KeyRunner SDK). The original
// KeyRunner-SDK agent is preserved in agent.keyrunner.ts.bak for a future v2.
// ---------------------------------------------------------------------------

import Anthropic from '@anthropic-ai/sdk';
import * as dotenv from 'dotenv';
import * as http from 'http';
import * as readline from 'readline';
import { SecurityPipeline, type PipelineConfig } from './src/pipeline';
import { DedupStore } from './src/dedup';
import type { ScanReport } from './src/types';

dotenv.config();

const PORT = parseInt(process.env.PORT ?? '3000', 10);

const num = (v: string | undefined, d: number): number => {
  const n = v != null ? Number(v) : NaN;
  return Number.isFinite(n) ? n : d;
};

// ── Config from env ───────────────────────────────────────────────────────────

const slackWebhookUrl = process.env.SLACK_WEBHOOK_URL;
const githubToken = process.env.GITHUB_TOKEN;
const githubRepo = process.env.GITHUB_REPO; // "owner/repo"

// Dry-run is OFF by default — the agent posts for real. Enable explicitly with DRY_RUN=true.
const canPost = Boolean((githubToken && githubRepo) || slackWebhookUrl);
const dryRun = (process.env.DRY_RUN ?? '').toLowerCase() === 'true';

const pipelineConfig: PipelineConfig = {
  research: {
    nvdDays: num(process.env.NVD_DAYS, 1),
    nvdLimit: num(process.env.NVD_LIMIT, 50),
    ghAdvisoryCount: num(process.env.GH_ADVISORY_COUNT, 30),
    maxEnrich: num(process.env.MAX_ENRICH, 12),
    nvdApiKey: process.env.NVD_API_KEY,
    githubToken,
  },
  action: {
    slackWebhookUrl,
    githubToken,
    githubRepo,
    issueLabels: (process.env.ISSUE_LABELS ?? 'security,vulnerability').split(',').map((s) => s.trim()).filter(Boolean),
    dryRun,
  },
};

const STATE_FILE = process.env.STATE_FILE ?? './.security-agent-state.json';
const SCAN_INTERVAL_MINUTES = num(process.env.SCAN_INTERVAL_MINUTES, 360); // default: every 6 hours (0 = disabled)
const SCAN_ON_START = (process.env.SCAN_ON_START ?? 'true').toLowerCase() === 'true'; // default: one scan at boot

const anthropic = new Anthropic();
const dedup = new DedupStore(STATE_FILE);
const pipeline = new SecurityPipeline(anthropic, pipelineConfig, dedup);

let scanning = false;
let lastReport: ScanReport | null = null;
let lastError: string | null = null;

async function runScan(overrideDryRun?: boolean): Promise<ScanReport> {
  if (scanning) throw new Error('a scan is already in progress');
  scanning = true;
  lastError = null;
  const prevDryRun = pipelineConfig.action.dryRun;
  if (overrideDryRun !== undefined) pipelineConfig.action.dryRun = overrideDryRun;
  try {
    lastReport = await pipeline.scan();
    return lastReport;
  } catch (err) {
    lastError = err instanceof Error ? err.message : String(err);
    throw err;
  } finally {
    pipelineConfig.action.dryRun = prevDryRun;
    scanning = false;
  }
}

// ── HTTP server — GET /health, POST /scan ──────────────────────────────────────

function startHttpServer(): void {
  const server = http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'ok',
          scanning,
          dryRun: pipelineConfig.action.dryRun,
          slackConfigured: Boolean(slackWebhookUrl),
          githubConfigured: Boolean(githubToken && githubRepo),
          githubRepo: githubRepo ?? null,
          lastScanAt: lastReport?.finishedAt ?? null,
          lastError,
        }),
      );
      return;
    }

    if (req.method === 'POST' && req.url?.startsWith('/scan')) {
      if (scanning) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'scan already in progress' }));
        return;
      }
      const url = new URL(req.url, `http://localhost:${PORT}`);
      const dryOverride = url.searchParams.has('dryRun')
        ? url.searchParams.get('dryRun') !== 'false'
        : undefined;
      try {
        const report = await runScan(dryOverride);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(report, null, 2));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
      }
      return;
    }

    res.writeHead(404);
    res.end();
  });

  server.listen(PORT, () => {
    console.log(`[server] listening on :${PORT}  — POST /scan  GET /health`);
  });
}

// ── Local REPL — press Enter to run a scan (only when interactive) ─────────────

function startRepl(): void {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const prompt = (): void => {
    rl.question('\n[security-agent] press Enter to scan (or type "dry" / "exit"): ', async (input) => {
      const cmd = input.trim().toLowerCase();
      if (cmd === 'exit') { rl.close(); return; }
      try {
        await runScan(cmd === 'dry' ? true : undefined);
      } catch (err) {
        console.error('[repl] scan failed:', err instanceof Error ? err.message : String(err));
      }
      prompt();
    });
  };
  prompt();
}

// ── Startup ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  startHttpServer();

  console.log(`[config] dryRun=${dryRun}  slack=${Boolean(slackWebhookUrl)}  github=${Boolean(githubToken && githubRepo)}${githubRepo ? ` (${githubRepo})` : ''}`);
  if (!dryRun && !canPost) {
    console.warn('[config] DRY_RUN is off but no SLACK_WEBHOOK_URL or GITHUB_TOKEN+GITHUB_REPO is set — actions will error until you configure them.');
  }

  if (SCAN_INTERVAL_MINUTES > 0) {
    console.log(`[scheduler] scanning every ${SCAN_INTERVAL_MINUTES} minute(s)`);
    setInterval(() => {
      runScan().catch((err) => console.error('[scheduler] scan failed:', err instanceof Error ? err.message : String(err)));
    }, SCAN_INTERVAL_MINUTES * 60 * 1000);
  }

  if (SCAN_ON_START) {
    runScan().catch((err) => console.error('[startup] scan failed:', err instanceof Error ? err.message : String(err)));
  }

  if (process.stdin.isTTY) startRepl();
}

main().catch((err) => {
  console.error('[Fatal]', err);
  process.exit(1);
});
