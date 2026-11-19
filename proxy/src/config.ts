import {
  DEFAULT_ALLOWED_HOSTS,
  FINDING_SEVERITIES,
  RESERVED_HOSTS,
  UPSTREAMS,
  type FindingSeverity,
  type Upstream,
} from "./constants.ts";

export interface Config {
  upstreams: Record<Upstream, string>;
  blockSeverity: FindingSeverity;
  suspiciousAction: "block" | "allow";
  scannerFailMode: "block" | "allow";
  judgeFailMode: "block" | "allow";
  judgeEnabled: boolean;
  judgeModel: string;
  judgeBlockThreshold: number;
  trustToolResults: boolean;
  allowedHosts: string[];
  denyServerTools: boolean;
  scannerTimeoutMs: number;
  judgeTimeoutMs: number;
  traceAgentSteps: number;
  traceMaxResultChars: number;
  auditMode: "off" | "all";
}

function oneOf<T extends string>(name: string, value: string | undefined, allowed: readonly T[], dflt: T): T {
  const v = (value ?? dflt) as T;
  if (!allowed.includes(v)) throw new Error(`invalid ${name}: ${value}`);
  return v;
}

function positiveInt(name: string, value: string | undefined, dflt: number): number {
  const n = value === undefined || value === "" ? dflt : Number(value);
  if (!Number.isInteger(n) || n <= 0) throw new Error(`invalid ${name}: ${value}`);
  return n;
}

function probability(name: string, value: string | undefined, dflt: number): number {
  const n = value === undefined || value === "" ? dflt : Number(value);
  if (!Number.isFinite(n) || n <= 0 || n > 1) throw new Error(`invalid ${name}: ${value}`);
  return n;
}

export function loadConfig(env: Record<string, unknown>): Config {
  const s = (k: string) => (typeof env[k] === "string" ? (env[k] as string) : undefined);
  const allowCustom = s("ALLOW_CUSTOM_UPSTREAM") === "true";
  const upstreams = {} as Record<Upstream, string>;
  for (const [name, { env: key, url }] of Object.entries(UPSTREAMS) as Array<
    [Upstream, { env: string; url: string }]
  >) {
    upstreams[name] = s(key) ?? url;
    if (!allowCustom && upstreams[name] !== url) throw new Error(`${key} must be ${url}`);
  }
  const extra = (s("EXTRA_ALLOWED_HOSTS") ?? "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  return {
    upstreams,
    blockSeverity: oneOf("BLOCK_SEVERITY", s("BLOCK_SEVERITY"), FINDING_SEVERITIES, "high"),
    suspiciousAction: oneOf("SUSPICIOUS_ACTION", s("SUSPICIOUS_ACTION"), ["block", "allow"] as const, "block"),
    scannerFailMode: oneOf("SCANNER_FAIL_MODE", s("SCANNER_FAIL_MODE"), ["block", "allow"] as const, "block"),
    judgeFailMode: oneOf("JUDGE_FAIL_MODE", s("JUDGE_FAIL_MODE"), ["block", "allow"] as const, "block"),
    judgeEnabled: oneOf("ENABLE_JUDGE", s("ENABLE_JUDGE"), ["true", "false"] as const, "true") === "true" && !!env.AI,
    judgeModel: s("JUDGE_MODEL") || "@cf/cloudflare/clef-flash",
    judgeBlockThreshold: probability("JUDGE_BLOCK_THRESHOLD", s("JUDGE_BLOCK_THRESHOLD"), 0.45),
    trustToolResults:
      oneOf("TRUST_TOOL_RESULTS", s("TRUST_TOOL_RESULTS"), ["true", "false"] as const, "false") === "true",
    allowedHosts: [...DEFAULT_ALLOWED_HOSTS, ...RESERVED_HOSTS, ...extra],
    denyServerTools: oneOf("SERVER_TOOLS", s("SERVER_TOOLS"), ["allow", "deny"] as const, "allow") === "deny",
    scannerTimeoutMs: positiveInt("SCANNER_TIMEOUT_MS", s("SCANNER_TIMEOUT_MS"), 5000),
    judgeTimeoutMs: positiveInt("JUDGE_TIMEOUT_MS", s("JUDGE_TIMEOUT_MS"), 15000),
    traceAgentSteps: positiveInt("TRACE_AGENT_STEPS", s("TRACE_AGENT_STEPS"), 20),
    traceMaxResultChars: positiveInt("TRACE_MAX_RESULT_CHARS", s("TRACE_MAX_RESULT_CHARS"), 2000),
    auditMode: oneOf("AUDIT_MODE", s("AUDIT_MODE"), ["off", "all"] as const, "all"),
  };
}
