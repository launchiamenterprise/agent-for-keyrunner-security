// ---------------------------------------------------------------------------
// Shared types for the Security Intelligence & Remediation Agent
// ---------------------------------------------------------------------------

/** One piece of corroborating evidence gathered by the Research Agent. */
export interface Evidence {
  source: 'NVD' | 'CISA_KEV' | 'GitHub_Advisory' | 'HackerNews' | 'Reddit';
  title: string;
  url?: string;
  /** Free-text detail (advisory summary, thread title, points/comments, etc.) */
  detail?: string;
}

/** Normalized, deduplicated view of a single CVE assembled from every feed. */
export interface ResearchFinding {
  cve: string;
  /** Human description of the vulnerability (from NVD). */
  description: string;
  /** CVSS v3.1 base score, if published. */
  cvss: number | null;
  cvssSeverity: string | null; // LOW | MEDIUM | HIGH | CRITICAL
  affectedSoftware: string[];
  /** Listed in CISA Known Exploited Vulnerabilities catalog. */
  cisaKev: boolean;
  cisaKevDueDate?: string;
  /** A public exploit / PoC is known (GitHub advisory, KEV, or chatter). */
  exploitKnown: boolean;
  publishedDate?: string;
  references: string[];
  evidence: Evidence[];
  /** How much social/community discussion we saw (HN + Reddit hits). */
  discussionCount: number;
}

export type RiskDecision = 'ignore' | 'monitor' | 'create_issue' | 'urgent';

/** The Risk Assessor (Claude) output for one CVE. */
export interface RiskAssessment {
  cve: string;
  decision: RiskDecision;
  /** 0-1 confidence in the decision. */
  confidence: number;
  /** Short risk label, e.g. "Critical", "High", "Low". */
  risk: string;
  /** One-paragraph plain summary of the vulnerability. */
  summary: string;
  /** Why this matters for the org right now. */
  whyItMatters: string;
  /** Concrete recommended mitigation / remediation. */
  recommendedAction: string;
  /** The model's reasoning for the decision (audit trail). */
  reasoning: string;
}

/** Result of attempting an action (Slack / GitHub) for a CVE. */
export interface ActionResult {
  cve: string;
  slackPosted: boolean;
  githubIssueUrl?: string;
  errors: string[];
}

/** Full output of one scan, returned by /scan and logged each run. */
export interface ScanReport {
  startedAt: string;
  finishedAt: string;
  totalFindings: number;
  newFindings: number;
  assessments: RiskAssessment[];
  actions: ActionResult[];
  skippedDuplicates: string[];
}
