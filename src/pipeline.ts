// ---------------------------------------------------------------------------
// Pipeline orchestrator — the multi-agent flow:
//
//   Research Agent → Risk Assessor (Claude) → Dedup gate → Action Agent
//
// Returns a ScanReport summarizing every decision and action.
// ---------------------------------------------------------------------------

import Anthropic from '@anthropic-ai/sdk';
import { runResearch, type ResearchConfig } from './research';
import { assessRisk } from './riskAssessor';
import { performAction, type ActionConfig } from './actions';
import { DedupStore } from './dedup';
import type { ActionResult, ResearchFinding, ScanReport } from './types';

export interface PipelineConfig {
  research: ResearchConfig;
  action: ActionConfig;
}

export class SecurityPipeline {
  constructor(
    private readonly anthropic: Anthropic,
    private readonly cfg: PipelineConfig,
    private readonly dedup: DedupStore,
  ) {}

  async scan(): Promise<ScanReport> {
    const startedAt = new Date().toISOString();
    console.log(`\n${'='.repeat(64)}\n[scan] started ${startedAt}\n${'='.repeat(64)}`);

    // 1. Research Agent — gather + normalize evidence
    const findings = await runResearch(this.cfg.research);
    const byCve = new Map<string, ResearchFinding>(findings.map((f) => [f.cve, f]));

    // 2. Risk Assessor — Claude decides per CVE
    const assessments = await assessRisk(this.anthropic, findings);

    // 3 + 4. Dedup gate → Action Agent
    const actions: ActionResult[] = [];
    const skippedDuplicates: string[] = [];
    let newFindings = 0;

    for (const a of assessments) {
      const finding = byCve.get(a.cve);
      if (!finding) continue;
      const actionable = a.decision === 'create_issue' || a.decision === 'urgent';
      if (!actionable) continue;

      if (this.dedup.hasActioned(a.cve)) {
        skippedDuplicates.push(a.cve);
        console.log(`[scan] ${a.cve} already actioned — skipping (dedup)`);
        continue;
      }

      newFindings += 1;
      const result = await performAction(this.cfg.action, finding, a);
      actions.push(result);
      // Only record as actioned if something actually succeeded (or dry-run).
      if (this.cfg.action.dryRun || result.githubIssueUrl || result.slackPosted) {
        this.dedup.markActioned(a.cve, a.decision, result.githubIssueUrl);
      }
    }

    const report: ScanReport = {
      startedAt,
      finishedAt: new Date().toISOString(),
      totalFindings: findings.length,
      newFindings,
      assessments,
      actions,
      skippedDuplicates,
    };

    this.logSummary(report);
    return report;
  }

  private logSummary(r: ScanReport): void {
    const counts = r.assessments.reduce<Record<string, number>>(
      (m, a) => ((m[a.decision] = (m[a.decision] ?? 0) + 1), m),
      {},
    );
    console.log(`\n${'='.repeat(64)}`);
    console.log(`[scan] complete — ${r.totalFindings} findings, decisions: ${JSON.stringify(counts)}`);
    console.log(`[scan] actioned ${r.newFindings} new, skipped ${r.skippedDuplicates.length} duplicate(s)`);
    for (const act of r.actions) {
      const bits = [
        act.githubIssueUrl ? `issue=${act.githubIssueUrl}` : null,
        act.slackPosted ? 'slack=posted' : null,
        act.errors.length ? `errors=${act.errors.join('; ')}` : null,
      ].filter(Boolean);
      console.log(`[scan]   ${act.cve}: ${bits.join(', ') || 'no-op'}`);
    }
    console.log(`${'='.repeat(64)}\n`);
  }
}
