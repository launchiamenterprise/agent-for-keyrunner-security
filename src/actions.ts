// ---------------------------------------------------------------------------
// Action Agent — performs the side effects. v1 calls Slack + GitHub DIRECTLY
// (Slack incoming webhook, GitHub REST API). No KeyRunner SDK in this version.
//
// Decisions:
//   create_issue → GitHub issue
//   urgent       → GitHub issue + Slack alert
// Content (issue body, Slack text) is templated from the research finding plus
// the LLM's assessment — the LLM made the decision; we format the output.
// ---------------------------------------------------------------------------

import type { ActionResult, ResearchFinding, RiskAssessment } from './types';

export interface ActionConfig {
  slackWebhookUrl?: string;
  githubToken?: string;
  githubRepo?: string; // "owner/repo"
  issueLabels: string[];
  /** When true, log what WOULD be sent but make no external calls. */
  dryRun: boolean;
}

// ── Content builders ──────────────────────────────────────────────────────────

function issueTitle(f: ResearchFinding, a: RiskAssessment): string {
  return `[${f.cve}] ${a.risk} severity vulnerability detected`;
}

function issueBody(f: ResearchFinding, a: RiskAssessment): string {
  const links = f.references.slice(0, 8).map((u) => `- ${u}`).join('\n') || '- (none)';
  const evidence =
    f.evidence
      .slice(0, 12)
      .map((e) => `- **${e.source}**: ${e.title}${e.detail ? ` — ${e.detail}` : ''}${e.url ? ` (${e.url})` : ''}`)
      .join('\n') || '- (none)';
  return [
    `## Summary`,
    a.summary || f.description,
    ``,
    `## Risk`,
    `**${a.risk}** — decision: \`${a.decision}\` · model confidence: ${(a.confidence * 100).toFixed(0)}%`,
    ``,
    `## CVSS`,
    `${f.cvss ?? 'unknown'} (${f.cvssSeverity ?? 'unknown'})`,
    ``,
    `## Affected software`,
    f.affectedSoftware.map((s) => `- ${s}`).join('\n') || '- unknown',
    ``,
    `## Exploit availability`,
    `- Public exploit / PoC: ${f.exploitKnown ? 'likely available' : 'unknown'}`,
    `- CISA Known Exploited (in the wild): ${f.cisaKev ? `YES${f.cisaKevDueDate ? ` (remediation due ${f.cisaKevDueDate})` : ''}` : 'no'}`,
    `- Community discussion (HN+Reddit): ${f.discussionCount} thread(s)`,
    ``,
    `## Why it matters`,
    a.whyItMatters,
    ``,
    `## Recommended mitigation`,
    a.recommendedAction,
    ``,
    `## Evidence`,
    evidence,
    ``,
    `## Links`,
    links,
    ``,
    `---`,
    `*Decision reasoning (Risk Assessor):* ${a.reasoning}`,
    `*Filed automatically by the Security Intelligence & Remediation Agent.*`,
  ].join('\n');
}

function slackPayload(f: ResearchFinding, a: RiskAssessment, issueUrl?: string): unknown {
  const fallback = `🚨 ${a.risk} vulnerability ${f.cve} (CVSS ${f.cvss ?? 'n/a'})`;
  const fields = [
    `*CVSS:* ${f.cvss ?? 'n/a'} (${f.cvssSeverity ?? 'n/a'})`,
    `*Public exploit:* ${f.exploitKnown ? 'Yes' : 'Unknown'}`,
    `*CISA KEV:* ${f.cisaKev ? 'Yes' : 'No'}`,
    `*Risk:* ${a.risk} (${(a.confidence * 100).toFixed(0)}% conf.)`,
  ];
  return {
    text: fallback,
    blocks: [
      { type: 'header', text: { type: 'plain_text', text: `🚨 Critical Vulnerability Detected`, emoji: true } },
      { type: 'section', text: { type: 'mrkdwn', text: `*<${f.cve}>* — ${a.summary || f.description}`.slice(0, 2900) } },
      { type: 'section', fields: fields.map((t) => ({ type: 'mrkdwn', text: t })) },
      { type: 'section', text: { type: 'mrkdwn', text: `*Why it matters:* ${a.whyItMatters}`.slice(0, 2900) } },
      { type: 'section', text: { type: 'mrkdwn', text: `*Recommended action:* ${a.recommendedAction}`.slice(0, 2900) } },
      ...(issueUrl ? [{ type: 'section', text: { type: 'mrkdwn', text: `*GitHub issue:* <${issueUrl}>` } }] : []),
    ],
  };
}

// ── Direct API calls ────────────────────────────────────────────────────────

async function createGitHubIssue(
  cfg: ActionConfig,
  title: string,
  body: string,
): Promise<string> {
  if (!cfg.githubToken || !cfg.githubRepo) {
    throw new Error('GITHUB_TOKEN and GITHUB_REPO are required to create issues');
  }
  const res = await fetch(`https://api.github.com/repos/${cfg.githubRepo}/issues`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${cfg.githubToken}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
      'User-Agent': 'security-intel-agent/1.0',
    },
    body: JSON.stringify({ title, body, labels: cfg.issueLabels }),
  });
  if (!res.ok) {
    throw new Error(`GitHub issue creation failed: HTTP ${res.status} ${await res.text()}`);
  }
  const data = (await res.json()) as { html_url: string };
  return data.html_url;
}

async function postSlack(cfg: ActionConfig, payload: unknown): Promise<void> {
  if (!cfg.slackWebhookUrl) throw new Error('SLACK_WEBHOOK_URL is required to post Slack alerts');
  const res = await fetch(cfg.slackWebhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Slack post failed: HTTP ${res.status} ${await res.text()}`);
}

// ── Orchestrated per-CVE action ───────────────────────────────────────────────

export async function performAction(
  cfg: ActionConfig,
  finding: ResearchFinding,
  assessment: RiskAssessment,
): Promise<ActionResult> {
  const result: ActionResult = { cve: finding.cve, slackPosted: false, errors: [] };
  const wantsIssue = assessment.decision === 'create_issue' || assessment.decision === 'urgent';
  const wantsSlack = assessment.decision === 'urgent';
  if (!wantsIssue && !wantsSlack) return result;

  const title = issueTitle(finding, assessment);
  const body = issueBody(finding, assessment);

  if (cfg.dryRun) {
    console.log(`\n[DRY RUN] ${finding.cve} → ${assessment.decision}`);
    if (wantsIssue) console.log(`[DRY RUN]   GitHub issue: ${title}`);
    if (wantsSlack) console.log(`[DRY RUN]   Slack alert would fire`);
    result.githubIssueUrl = wantsIssue ? '(dry-run)' : undefined;
    result.slackPosted = wantsSlack;
    return result;
  }

  if (wantsIssue) {
    try {
      result.githubIssueUrl = await createGitHubIssue(cfg, title, body);
      console.log(`[action] ${finding.cve} → GitHub issue ${result.githubIssueUrl}`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      result.errors.push(`github: ${msg}`);
      console.error(`[action] ${finding.cve} GitHub error: ${msg}`);
    }
  }

  if (wantsSlack) {
    try {
      await postSlack(cfg, slackPayload(finding, assessment, result.githubIssueUrl));
      result.slackPosted = true;
      console.log(`[action] ${finding.cve} → Slack alert posted`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      result.errors.push(`slack: ${msg}`);
      console.error(`[action] ${finding.cve} Slack error: ${msg}`);
    }
  }

  return result;
}
