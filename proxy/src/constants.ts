export const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;
export type Severity = keyof typeof SEVERITY_RANK;
/** Severities a finding can carry; anything else is treated as critical. */
export const FINDING_SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type FindingSeverity = (typeof FINDING_SEVERITIES)[number];

export const findingSeverity = (s: unknown): FindingSeverity =>
  FINDING_SEVERITIES.includes(s as FindingSeverity) ? (s as FindingSeverity) : "critical";
export const rank = (s: Severity) => SEVERITY_RANK[s];

export const DEFAULT_ALLOWED_HOSTS = [
  "localhost",
  "127.0.0.1",
  "::1",
  "pypi.org",
  "files.pythonhosted.org",
  "registry.npmjs.org",
  "crates.io",
  "static.crates.io",
  "index.crates.io",
];
// RFC 2606: unregistrable, so a call reaches no one through them.
export const RESERVED_HOSTS = ["example.com", "example.net", "example.org"];

export const SELF_PROTECT_PATTERN =
  /\b(?:ANTHROPIC_BASE_URL|OPENAI_BASE_URL|ANTHROPIC_CUSTOM_HEADERS|x-saferagents-key)\b/i;

// Commands and APIs that reach a host (superset of upstream NETWORK_PATTERN).
export const NETWORK_PATTERN = new RegExp(
  [
    String.raw`\b(?:curl|wget|nc|ncat|netcat|telnet|ssh|scp|sftp|rsync|ftp|socat|aria2c|dig|nslookup)\s`,
    String.raw`\bgit\s+(?:clone|fetch|pull|push|ls-remote|remote\s+(?:add|set-url))\b`,
    String.raw`\b(?:pip3?|uv\s+pip)\s+install\b`,
    String.raw`\bnpm\s+(?:install|i|publish)\b`,
    String.raw`/dev/(?:tcp|udp)/`,
    String.raw`\brequests\.(?:get|post|put|patch|delete|head|options|request|Session)\b`,
    String.raw`\burlopen\(|\burllib\.request\b|\bhttpx\.|\baiohttp\.|\bhttp\.client\b`,
    String.raw`\bsocket\.(?:socket|create_connection)\b|\bfetch\(`,
    String.raw`\bInvoke-(?:WebRequest|RestMethod)\b|\bopenssl\s+s_client\b`,
  ].join("|"),
  "i",
);
// Tools that reach a URL by themselves, whatever their arguments say.
export const NETWORK_TOOL_PATTERN = /fetch|browse|browser|web|http|url|download/i;

// A network command and its arguments up to the next shell separator.
export const TARGET_SEGMENT =
  /\b(?:curl|wget|nc|ncat|netcat|telnet|ssh|scp|sftp|rsync|ftp|socat|aria2c|dig|nslookup|git\s+(?:clone|fetch|pull|push|ls-remote|remote\s+(?:add|set-url)))\b([^\n|;&]*)/gi;

export const AUTHORITY = /:\/\/((?:[^\s/?#"'\\`)\]>@]*@)?(?:\[[0-9a-f:.]+\]|[^\s/?#"'\\`)\]>]*))/gi;
export const IPV4 = /(?<![\d.=])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/g;
export const DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$/;
export const NUMERIC_HOST = /^(?:(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){3}|0x[0-9a-f]+|\d{8,})$/;
// Bare tokens ending in these labels are treated as files, not hosts (see §10).
export const FILE_EXTENSIONS = new Set([
  "sh",
  "py",
  "md",
  "txt",
  "json",
  "js",
  "ts",
  "zip",
  "gz",
  "tgz",
  "tar",
  "bz2",
  "xz",
  "log",
  "csv",
  "yaml",
  "yml",
  "toml",
  "lock",
  "whl",
  "rs",
  "go",
  "rb",
  "pl",
  "php",
  "html",
  "css",
  "xml",
  "pem",
  "key",
  "crt",
  "conf",
  "cfg",
  "ini",
  "env",
  "out",
  "bin",
  "exe",
  "so",
  "dylib",
  "deb",
  "rpm",
]);
