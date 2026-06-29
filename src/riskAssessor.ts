// ---------------------------------------------------------------------------
// Risk Assessor Agent — the DECISION ENGINE. Claude reads the research evidence
// for each CVE and decides what to do. There is deliberately NO hardcoded
// `if (cvss > 9)` rule here — the model weighs CVSS, exploit status, CISA KEV,
// and community chatter together and returns a decision + confidence + reasoning.
// ---------------------------------------------------------------------------

import Anthropic from '@anthropic-ai/sdk';
import type { ResearchFinding, RiskAssessment, RiskDecision } from './types';
import { findingToPromptBlock } from './research';

const MODEL = process.env.RISK_MODEL ?? 'claude-sonnet-4-6';

const SYSTEM = `You are a senior security analyst triaging newly disclosed vulnerabilities for an
engineering organization. For EACH CVE you are given, decide what the team should do.

Weigh ALL signals together — do not rely on CVSS alone:
- CVSS base score and severity
- Whether a public exploit / PoC exists
- Whether CISA lists it as Known Exploited (actively exploited in the wild = much higher urgency)
- How much the security community is discussing it (HackerNews / Reddit)
- The affected software and how widespread / internet-facing it is

Decision scale:
- "ignore": low risk, theoretical, or not relevant to a typical org. No action.
- "monitor": worth tracking but no action yet (no confirmed exploit, moderate severity).
- "create_issue": a real, actionable vulnerability the team should patch. Open a GitHub issue.
- "urgent": critical + (exploited in the wild OR public exploit) + widespread. Open an issue AND
  fire a Slack alert so a human sees it immediately.

Be selective. In a normal batch most CVEs are "ignore" or "monitor"; only genuinely dangerous,
actionable ones are "create_issue" or "urgent". Provide a calibrated confidence (0-1) and concise,
specific reasoning that a human could audit.`;

// Forced-tool schema → guarantees structured, parseable output.
const SUBMIT_TOOL: Anthropic.Tool = {
  name: 'submit_assessments',
  description: 'Submit the triage decision for every CVE provided.',
  input_schema: {
    type: 'object',
    properties: {
      assessments: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            cve: { type: 'string' },
            decision: { type: 'string', enum: ['ignore', 'monitor', 'create_issue', 'urgent'] },
            confidence: { type: 'number', description: '0 to 1' },
            risk: { type: 'string', description: 'Short label: Critical | High | Medium | Low' },
            summary: { type: 'string', description: 'One-paragraph plain-English summary.' },
            whyItMatters: { type: 'string', description: 'Why this matters for the org right now.' },
            recommendedAction: { type: 'string', description: 'Concrete remediation / mitigation.' },
            reasoning: { type: 'string', description: 'Audit trail for the decision.' },
          },
          required: ['cve', 'decision', 'confidence', 'risk', 'summary', 'whyItMatters', 'recommendedAction', 'reasoning'],
        },
      },
    },
    required: ['assessments'],
  },
};

const DECISIONS: RiskDecision[] = ['ignore', 'monitor', 'create_issue', 'urgent'];

// Triaging many CVEs in one forced-tool call overflows max_tokens and truncates the
// JSON, so we batch. Each batch is a self-contained structured call.
const BATCH_SIZE = Number(process.env.ASSESS_BATCH_SIZE ?? 10);

async function assessBatch(
  anthropic: Anthropic,
  findings: ResearchFinding[],
): Promise<RiskAssessment[]> {
  const prompt =
    `Triage the following ${findings.length} CVE(s). Call submit_assessments with EXACTLY one entry per CVE.\n\n` +
    findings.map((f, i) => `--- CVE ${i + 1} ---\n${findingToPromptBlock(f)}`).join('\n\n');

  const response = await anthropic.messages.create({
    model: MODEL,
    max_tokens: 8192,
    system: SYSTEM,
    tools: [SUBMIT_TOOL],
    tool_choice: { type: 'tool', name: 'submit_assessments' },
    messages: [{ role: 'user', content: prompt }],
  });

  const toolUse = response.content.find(
    (b): b is Anthropic.ToolUseBlock => b.type === 'tool_use' && b.name === 'submit_assessments',
  );
  if (!toolUse) {
    console.warn(`[risk] batch produced no tool_use (stop_reason=${response.stop_reason})`);
    return [];
  }

  const raw = (toolUse.input as { assessments?: unknown[] }).assessments ?? [];
  const valid = new Set(findings.map((f) => f.cve));
  const out: RiskAssessment[] = [];
  for (const a of raw as any[]) {
    if (!a?.cve || !valid.has(a.cve)) continue;
    const decision: RiskDecision = DECISIONS.includes(a.decision) ? a.decision : 'monitor';
    out.push({
      cve: a.cve,
      decision,
      confidence: typeof a.confidence === 'number' ? Math.max(0, Math.min(1, a.confidence)) : 0.5,
      risk: String(a.risk ?? 'Unknown'),
      summary: String(a.summary ?? ''),
      whyItMatters: String(a.whyItMatters ?? ''),
      recommendedAction: String(a.recommendedAction ?? ''),
      reasoning: String(a.reasoning ?? ''),
    });
  }
  return out;
}

export async function assessRisk(
  anthropic: Anthropic,
  findings: ResearchFinding[],
): Promise<RiskAssessment[]> {
  if (findings.length === 0) return [];

  const batches: ResearchFinding[][] = [];
  for (let i = 0; i < findings.length; i += BATCH_SIZE) batches.push(findings.slice(i, i + BATCH_SIZE));

  console.log(`[risk] asking ${MODEL} to triage ${findings.length} CVE(s) in ${batches.length} batch(es)…`);
  const results = await Promise.all(batches.map((b) => assessBatch(anthropic, b)));
  const assessments = results.flat();

  const counts = assessments.reduce<Record<string, number>>((m, a) => ((m[a.decision] = (m[a.decision] ?? 0) + 1), m), {});
  console.log(`[risk] ${assessments.length} assessments, decisions: ${JSON.stringify(counts)}`);
  return assessments;
}
