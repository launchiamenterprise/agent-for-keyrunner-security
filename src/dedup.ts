// ---------------------------------------------------------------------------
// Deduplication store — remembers which CVEs we already acted on so repeated
// scans don't re-file issues / re-alert. File-backed JSON (best-effort).
//
// Note: in k8s without a mounted volume this resets on pod restart. For the demo
// that's fine; for production point KR_STATE_FILE at a PVC or swap for a DB.
// ---------------------------------------------------------------------------

import * as fs from 'fs';

interface SeenRecord {
  decision: string;
  actedOn: string; // ISO timestamp
  githubIssueUrl?: string;
}

export class DedupStore {
  private seen: Record<string, SeenRecord> = {};

  constructor(private readonly file: string) {
    this.load();
  }

  private load(): void {
    try {
      if (fs.existsSync(this.file)) {
        this.seen = JSON.parse(fs.readFileSync(this.file, 'utf8'));
        console.log(`[dedup] loaded ${Object.keys(this.seen).length} seen CVE(s) from ${this.file}`);
      }
    } catch (err) {
      console.warn(`[dedup] could not load state: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  private save(): void {
    try {
      fs.writeFileSync(this.file, JSON.stringify(this.seen, null, 2));
    } catch (err) {
      console.warn(`[dedup] could not persist state: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /** Have we already acted on this CVE (filed an issue / alerted)? */
  hasActioned(cve: string): boolean {
    return cve in this.seen;
  }

  markActioned(cve: string, decision: string, githubIssueUrl?: string): void {
    this.seen[cve] = { decision, actedOn: new Date().toISOString(), githubIssueUrl };
    this.save();
  }
}
