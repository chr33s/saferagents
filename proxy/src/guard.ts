import type { Config } from "./config.ts";
import { findingSeverity, rank } from "./constants.ts";
import type { Conversation } from "./conversation.ts";
import { runJudge, taskText } from "./judge.ts";
import { checkPolicy, type RequestPolicy } from "./policy.ts";
import { atifArguments, buildTrace } from "./trace.ts";
import type { AtifStep, Env, Finding } from "./types.ts";
import { withTimeout } from "./util.ts";

export type Verdict = "passed" | "suspicious" | "blocked";
export interface Review {
  verdict: Verdict;
  reason?: string;
  findings: Finding[];
  judge?: string;
  note?: string;
}
export interface AuditRecord extends Review {
  tool: string;
  arguments: string;
}
export type Decision = { keep: true } | { keep: false; notice: string };

/** Per response, or per OpenAI choice: the stop reason becomes end-of-turn only when nothing was kept. */
export class Tally {
  private kept = 0;
  private blocked = 0;

  add(d: Decision): Decision {
    if (d.keep) this.kept++;
    else this.blocked++;
    return d;
  }

  get endTurn(): boolean {
    return this.blocked > 0 && this.kept === 0;
  }
}

const fmt = (fs: Finding[]) => fs.map((f) => `${f.ruleId} (${f.severity})`).join(", ");

export class Guard {
  private readonly calls: Array<{ name: string; arguments: Record<string, unknown> }> = [];
  private steps?: AtifStep[];
  private readonly conv: Conversation;
  private readonly policy: RequestPolicy;
  private readonly cfg: Config;
  private readonly env: Env;
  private readonly audit: (rec: AuditRecord) => void;

  constructor(conv: Conversation, policy: RequestPolicy, cfg: Config, env: Env, audit: (rec: AuditRecord) => void) {
    this.conv = conv;
    this.policy = policy;
    this.cfg = cfg;
    this.env = env;
    this.audit = audit;
  }

  /** Reviews one complete call. Every non-passed review is audited. */
  async review(name: string, args: string): Promise<Decision> {
    const r = await this.assess(name, args);
    if (r.verdict !== "passed" || r.note) this.audit({ ...r, tool: name, arguments: args });
    if (r.verdict !== "blocked") return { keep: true };
    return { keep: false, notice: `[saferagents] blocked call to \`${name}\`: ${r.reason}` };
  }

  private async assess(name: string, args: string): Promise<Review> {
    this.calls.push({ name, arguments: atifArguments(args) });
    const p = checkPolicy(name, args, this.policy);
    if (p.action === "block") return { verdict: "blocked", reason: `${p.ruleId}: ${p.reason}`, findings: [] };

    let findings: Finding[] = [];
    let note: string | undefined;
    try {
      findings = await this.scan();
    } catch (e) {
      if (this.cfg.scannerFailMode === "block") {
        return { verdict: "blocked", reason: "SCANNER-ERROR: scanner unavailable", findings: [], note: String(e) };
      }
      note = `scanner_error: ${e}`;
    }

    const severe = findings.filter((f) => rank(f.severity) >= rank(this.cfg.blockSeverity));
    if (severe.length) return { verdict: "blocked", reason: `atif-scan: ${fmt(severe)}`, findings, note };

    const suspicious =
      p.action === "suspicious"
        ? [{ ruleId: p.ruleId, severity: "medium" as const, title: p.reason }, ...findings]
        : findings;
    if (!suspicious.length) return { verdict: "passed", findings: [], note };

    // No judge falls back to SUSPICIOUS_ACTION; a judge error falls back to JUDGE_FAIL_MODE.
    const j = this.cfg.judgeEnabled ? await this.judge(name, args, suspicious) : null;
    const block = j
      ? j.verdict === "block" || (j.verdict === "error" && this.cfg.judgeFailMode === "block")
      : this.cfg.suspiciousAction === "block";
    const base = { findings: suspicious, note, ...(j && { judge: `${j.verdict}: ${j.detail}` }) };
    if (!block) return { verdict: "suspicious", ...base };
    const why = !j ? "no judge configured" : j.verdict === "block" ? `judge: ${j.detail}` : "judge unavailable";
    return { verdict: "blocked", reason: `${fmt(suspicious)}; ${why}`, ...base };
  }

  private async judge(name: string, args: string, findings: Finding[]) {
    try {
      const j = await runJudge(this.env.AI, this.cfg, taskText(this.conv), name, args, findings);
      return { verdict: j.verdict, detail: j.reason };
    } catch (e) {
      return { verdict: "error" as const, detail: String(e) };
    }
  }

  private async scan(): Promise<Finding[]> {
    this.steps ??= buildTrace(this.conv, this.cfg.traceAgentSteps, this.cfg.traceMaxResultChars);
    const payload = JSON.stringify({ steps: this.steps, calls: this.calls });
    const raw = await withTimeout(this.env.ATIF_SCANNER.scan(payload), this.cfg.scannerTimeoutMs, "scanner timeout");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed?.findings)) throw new Error("malformed scanner response");
    return parsed.findings.map((f: any) => ({
      ruleId: String(f?.ruleId ?? "unknown"),
      severity: findingSeverity(f?.severity),
      title: String(f?.title ?? ""),
    }));
  }
}
