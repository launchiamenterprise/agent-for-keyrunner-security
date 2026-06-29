// ---------------------------------------------------------------------------
// Research Agent — collects every feed and assembles a normalized, deduplicated
// per-CVE view with evidence. Deterministic (no LLM): the LLM reasons over the
// EVIDENCE this produces, in the Risk Assessor.
// ---------------------------------------------------------------------------

import {
  fetchNvdRecent,
  fetchCisaKev,
  fetchGitHubAdvisories,
  searchHackerNews,
  searchReddit,
} from './feeds';
import type { Evidence, ResearchFinding } from './types';

export interface ResearchConfig {
  nvdDays: number;
  nvdLimit: number;
  ghAdvisoryCount: number;
  /** Cap how many CVEs we enrich with HN/Reddit search (limits API calls + latency). */
  maxEnrich: number;
  nvdApiKey?: string;
  githubToken?: string;
}

const sevRank = (s: string | null): number =>
  ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 } as Record<string, number>)[(s ?? '').toUpperCase()] ?? 0;

export async function runResearch(cfg: ResearchConfig): Promise<ResearchFinding[]> {
  console.log('[research] fetching feeds: NVD, CISA KEV, GitHub Advisories…');
  const [nvd, kev, ghAdv] = await Promise.all([
    fetchNvdRecent({ days: cfg.nvdDays, limit: cfg.nvdLimit, apiKey: cfg.nvdApiKey }),
    fetchCisaKev(),
    fetchGitHubAdvisories({ perPage: cfg.ghAdvisoryCount, token: cfg.githubToken }),
  ]);
  console.log(`[research] NVD=${nvd.length}  KEV=${kev.size}  GH-Advisories=${ghAdv.length}`);

  // Index GitHub advisories by CVE id
  const ghByCve = new Map<string, typeof ghAdv>();
  for (const a of ghAdv) {
    if (!a.cveId) continue;
    const arr = ghByCve.get(a.cveId) ?? [];
    arr.push(a);
    ghByCve.set(a.cveId, arr);
  }

  // Seed findings from NVD, then fold in any KEV/advisory CVEs NVD didn't return.
  const findings = new Map<string, ResearchFinding>();

  const ensure = (cve: string): ResearchFinding => {
    let f = findings.get(cve);
    if (!f) {
      f = {
        cve,
        description: '',
        cvss: null,
        cvssSeverity: null,
        affectedSoftware: [],
        cisaKev: false,
        exploitKnown: false,
        references: [],
        evidence: [],
        discussionCount: 0,
      };
      findings.set(cve, f);
    }
    return f;
  };

  for (const c of nvd) {
    const f = ensure(c.id);
    f.description = c.description;
    f.cvss = c.cvss;
    f.cvssSeverity = c.cvssSeverity;
    f.affectedSoftware = c.affectedSoftware;
    f.publishedDate = c.publishedDate;
    f.references = c.references;
    f.evidence.push({
      source: 'NVD',
      title: c.id,
      detail: `CVSS ${c.cvss ?? 'n/a'} (${c.cvssSeverity ?? 'n/a'}). ${c.description.slice(0, 240)}`,
    });
  }

  // CISA KEV — strong "actively exploited" signal.
  for (const [cve, entry] of kev) {
    // Only fold KEV-only CVEs in if they were also published recently OR have an advisory,
    // to avoid dumping the entire historical KEV catalog into each scan.
    const isKnown = findings.has(cve) || ghByCve.has(cve);
    if (!isKnown) continue;
    const f = ensure(cve);
    f.cisaKev = true;
    f.exploitKnown = true;
    f.cisaKevDueDate = entry.dueDate;
    if (!f.affectedSoftware.length) f.affectedSoftware = [`${entry.vendorProject} ${entry.product}`.trim()];
    f.evidence.push({
      source: 'CISA_KEV',
      title: entry.vulnerabilityName || cve,
      url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      detail:
        `Listed in CISA KEV (actively exploited). Vendor: ${entry.vendorProject}, product: ${entry.product}.` +
        (entry.dueDate ? ` Federal remediation due ${entry.dueDate}.` : '') +
        (entry.knownRansomwareCampaignUse && entry.knownRansomwareCampaignUse !== 'Unknown'
          ? ` Ransomware: ${entry.knownRansomwareCampaignUse}.`
          : ''),
    });
  }

  // GitHub advisories — exploit/PoC + curated severity + affected packages.
  for (const [cve, advs] of ghByCve) {
    const f = ensure(cve);
    f.exploitKnown = true; // a published advisory implies a known, analyzed vuln
    for (const a of advs) {
      if (!f.description) f.description = a.summary;
      f.references.push(...a.references, a.url);
      f.evidence.push({
        source: 'GitHub_Advisory',
        title: a.summary || a.ghsaId,
        url: a.url,
        detail: `GHSA ${a.ghsaId}, severity ${a.severity}.`,
      });
    }
  }

  let list = [...findings.values()];

  // Choose which CVEs are worth enriching with social chatter (caps API calls).
  // This is ONLY a fetch-budget filter — it never decides risk (Claude does that).
  const enrichCandidates = list
    .slice()
    .sort((a, b) => {
      if (a.cisaKev !== b.cisaKev) return a.cisaKev ? -1 : 1;
      const s = (b.cvss ?? 0) - (a.cvss ?? 0);
      if (s !== 0) return s;
      return sevRank(b.cvssSeverity) - sevRank(a.cvssSeverity);
    })
    .slice(0, cfg.maxEnrich);

  console.log(`[research] enriching ${enrichCandidates.length} CVEs with HackerNews + Reddit…`);
  await Promise.all(
    enrichCandidates.map(async (f) => {
      const [hn, rd] = await Promise.all([searchHackerNews(f.cve), searchReddit(f.cve)]);
      for (const h of hn) {
        f.discussionCount += 1;
        f.evidence.push({
          source: 'HackerNews',
          title: h.title,
          url: h.url,
          detail: `${h.points} points, ${h.numComments} comments`,
        });
        if (/exploit|poc|proof.of.concept|in the wild/i.test(h.title)) f.exploitKnown = true;
      }
      for (const r of rd) {
        f.discussionCount += 1;
        f.evidence.push({
          source: 'Reddit',
          title: r.title,
          url: r.url,
          detail: `r/${r.subreddit}, ${r.ups} upvotes, ${r.numComments} comments`,
        });
        if (/exploit|poc|proof.of.concept|in the wild/i.test(r.title)) f.exploitKnown = true;
      }
    }),
  );

  // De-dupe reference URLs and surface the most relevant findings first.
  for (const f of list) f.references = [...new Set(f.references)].slice(0, 10);
  list = list.sort((a, b) => {
    if (a.cisaKev !== b.cisaKev) return a.cisaKev ? -1 : 1;
    return (b.cvss ?? 0) - (a.cvss ?? 0);
  });

  console.log(`[research] assembled ${list.length} findings`);
  return list;
}

/** Compact, model-friendly rendering of one finding for the Risk Assessor prompt. */
export function findingToPromptBlock(f: ResearchFinding): string {
  const ev: Evidence[] = f.evidence.slice(0, 12);
  return [
    `CVE: ${f.cve}`,
    `CVSS: ${f.cvss ?? 'unknown'} (${f.cvssSeverity ?? 'unknown'})`,
    `CISA KEV (actively exploited): ${f.cisaKev ? 'YES' : 'no'}${f.cisaKevDueDate ? ` (due ${f.cisaKevDueDate})` : ''}`,
    `Public exploit / PoC known: ${f.exploitKnown ? 'likely' : 'unknown'}`,
    `Affected: ${f.affectedSoftware.join(', ') || 'unknown'}`,
    `Community discussion (HN+Reddit hits): ${f.discussionCount}`,
    `Description: ${f.description.slice(0, 400)}`,
    `Evidence:`,
    ...ev.map((e) => `  - [${e.source}] ${e.title}${e.detail ? ` — ${e.detail}` : ''}`),
  ].join('\n');
}
