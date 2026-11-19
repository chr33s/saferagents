// Best effort: the audit bucket must stay private (§8).
const PATTERNS: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED:private_key]"],
  [/\bsk-ant-[A-Za-z0-9_-]{20,}/g, "[REDACTED:anthropic_key]"],
  [/\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g, "[REDACTED:openai_key]"],
  [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}/g, "[REDACTED:github_token]"],
  [/\bhf_[A-Za-z0-9]{30,}\b/g, "[REDACTED:hf_token]"],
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, "[REDACTED:aws_key_id]"],
  [/(aws_secret_access_key\s*[=:]\s*)\S+/gi, "$1[REDACTED]"],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, "[REDACTED:slack_token]"],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "[REDACTED:jwt]"],
  [/(authorization\s*:\s*(?:bearer|basic)\s+)\S+/gi, "$1[REDACTED]"],
  [/((?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)["']?[^\s"']{6,}/gi, "$1[REDACTED]"],
];

export function scrub(text: string): string {
  return PATTERNS.reduce((t, [re, rep]) => t.replace(re, rep), text);
}
