// ---------------------------------------------------------------------------
// Security feed fetchers — all PUBLIC APIs, called directly (v1, no KeyRunner SDK).
// Every fetcher is defensive: it times out and returns [] on failure so one bad
// feed never sinks the whole scan.
// ---------------------------------------------------------------------------

const UA = 'security-intel-agent/1.0 (demo)';

async function fetchJson<T>(
  url: string,
  opts: { headers?: Record<string, string>; timeoutMs?: number } = {},
): Promise<T | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15_000);
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': UA, Accept: 'application/json', ...opts.headers },
      signal: controller.signal,
    });
    if (!res.ok) {
      console.warn(`[feed] ${url} → HTTP ${res.status}`);
      return null;
    }
    return (await res.json()) as T;
  } catch (err) {
    console.warn(`[feed] ${url} failed: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ── NVD CVE API ──────────────────────────────────────────────────────────────
// https://nvd.nist.gov/developers/vulnerabilities

export interface NvdCve {
  id: string;
  description: string;
  cvss: number | null;
  cvssSeverity: string | null;
  publishedDate?: string;
  references: string[];
  affectedSoftware: string[];
}

export async function fetchNvdRecent(opts: { days: number; limit: number; apiKey?: string }): Promise<NvdCve[]> {
  const end = new Date();
  const start = new Date(end.getTime() - opts.days * 24 * 60 * 60 * 1000);
  const iso = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, '.000');
  const url =
    `https://services.nvd.nist.gov/rest/json/cves/2.0` +
    `?pubStartDate=${encodeURIComponent(iso(start))}` +
    `&pubEndDate=${encodeURIComponent(iso(end))}` +
    `&resultsPerPage=${Math.min(opts.limit, 2000)}`;

  const data = await fetchJson<any>(url, {
    headers: opts.apiKey ? { apiKey: opts.apiKey } : {},
    timeoutMs: 30_000,
  });
  if (!data?.vulnerabilities) return [];

  return (data.vulnerabilities as any[]).map((v) => {
    const cve = v.cve ?? {};
    const metric =
      cve.metrics?.cvssMetricV31?.[0]?.cvssData ??
      cve.metrics?.cvssMetricV30?.[0]?.cvssData ??
      null;
    const descEn = (cve.descriptions as any[] | undefined)?.find((d) => d.lang === 'en');
    const affected = new Set<string>();
    for (const cfg of (cve.configurations as any[] | undefined) ?? []) {
      for (const node of cfg.nodes ?? []) {
        for (const m of node.cpeMatch ?? []) {
          // cpe:2.3:a:vendor:product:version:...
          const parts = String(m.criteria ?? '').split(':');
          if (parts.length > 4 && parts[3] && parts[4]) affected.add(`${parts[3]} ${parts[4]}`.replace(/[*_]/g, ' ').trim());
        }
      }
    }
    return {
      id: cve.id,
      description: descEn?.value ?? '(no description)',
      cvss: metric?.baseScore ?? null,
      cvssSeverity: metric?.baseSeverity ?? null,
      publishedDate: cve.published,
      references: ((cve.references as any[] | undefined) ?? []).map((r) => r.url).filter(Boolean).slice(0, 8),
      affectedSoftware: [...affected].slice(0, 10),
    } as NvdCve;
  }).filter((c) => c.id);
}

// ── CISA Known Exploited Vulnerabilities ──────────────────────────────────────

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
}

export async function fetchCisaKev(): Promise<Map<string, KevEntry>> {
  const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  const data = await fetchJson<{ vulnerabilities: KevEntry[] }>(url, { timeoutMs: 30_000 });
  const map = new Map<string, KevEntry>();
  for (const v of data?.vulnerabilities ?? []) map.set(v.cveID, v);
  return map;
}

// ── GitHub Security Advisories ────────────────────────────────────────────────
// https://docs.github.com/rest/security-advisories/global-advisories

export interface GhAdvisory {
  cveId: string | null;
  ghsaId: string;
  summary: string;
  severity: string; // low | medium | high | critical
  url: string;
  references: string[];
}

export async function fetchGitHubAdvisories(opts: { perPage: number; token?: string }): Promise<GhAdvisory[]> {
  const url = `https://api.github.com/advisories?per_page=${Math.min(opts.perPage, 100)}&sort=published&direction=desc`;
  const data = await fetchJson<any[]>(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(opts.token ? { Authorization: `Bearer ${opts.token}` } : {}),
    },
  });
  if (!Array.isArray(data)) return [];
  return data.map((a) => ({
    cveId: a.cve_id ?? null,
    ghsaId: a.ghsa_id,
    summary: a.summary ?? '',
    severity: a.severity ?? 'unknown',
    url: a.html_url ?? a.url ?? '',
    references: (a.references as any[] | undefined)?.map((r) => r.url ?? r).filter(Boolean).slice(0, 5) ?? [],
  }));
}

// ── HackerNews (Algolia search) ───────────────────────────────────────────────

export interface HnHit {
  title: string;
  url?: string;
  points: number;
  numComments: number;
  objectID: string;
}

export async function searchHackerNews(query: string): Promise<HnHit[]> {
  const url = `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(query)}&tags=story&hitsPerPage=5`;
  const data = await fetchJson<any>(url, { timeoutMs: 10_000 });
  return ((data?.hits as any[]) ?? []).map((h) => ({
    title: h.title ?? h.story_title ?? '(untitled)',
    url: h.url ?? `https://news.ycombinator.com/item?id=${h.objectID}`,
    points: h.points ?? 0,
    numComments: h.num_comments ?? 0,
    objectID: h.objectID,
  }));
}

// ── Reddit search ─────────────────────────────────────────────────────────────

export interface RedditHit {
  title: string;
  url: string;
  ups: number;
  numComments: number;
  subreddit: string;
}

export async function searchReddit(query: string): Promise<RedditHit[]> {
  // Reddit increasingly 403s unauthenticated JSON from datacenter IPs / generic UAs.
  // Best-effort: try old.reddit.com then www, with a Reddit-style UA. Degrades to [].
  const q = encodeURIComponent(query);
  const hosts = ['https://old.reddit.com', 'https://www.reddit.com'];
  for (const host of hosts) {
    const data = await fetchJson<any>(`${host}/search.json?q=${q}&sort=new&limit=5`, {
      timeoutMs: 10_000,
      headers: { 'User-Agent': 'web:security-intel-agent:1.0 (security triage demo)' },
    });
    const children = data?.data?.children as any[] | undefined;
    if (children) {
      return children.map((c) => ({
        title: c.data?.title ?? '(untitled)',
        url: `https://www.reddit.com${c.data?.permalink ?? ''}`,
        ups: c.data?.ups ?? 0,
        numComments: c.data?.num_comments ?? 0,
        subreddit: c.data?.subreddit ?? '',
      }));
    }
  }
  return [];
}
