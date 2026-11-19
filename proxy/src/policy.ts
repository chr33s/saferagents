import {
  AUTHORITY,
  DOMAIN,
  FILE_EXTENSIONS,
  IPV4,
  NETWORK_PATTERN,
  NETWORK_TOOL_PATTERN,
  NUMERIC_HOST,
  SELF_PROTECT_PATTERN,
  TARGET_SEGMENT,
} from "./constants.ts";
import { isObject, type Conversation } from "./conversation.ts";

export type PolicyResult = { action: "pass" } | { action: "block" | "suspicious"; ruleId: string; reason: string };

export interface RequestPolicy {
  declared: Set<string>;
  ctxText: string;
  ctxHosts: Set<string>;
  allowed: string[];
}

export function walkStrings(value: unknown, out: string[]): void {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const v of value) walkStrings(v, out);
  else if (value && typeof value === "object") for (const v of Object.values(value)) walkStrings(v, out);
}

/** Every string value of the JSON arguments, decoded (upstream call_text). */
export function callText(args: string): string {
  try {
    const out: string[] = [];
    walkStrings(JSON.parse(args), out);
    return out.join("\n");
  } catch {
    return args;
  }
}

const bare = (h: string) => h.replace(/^\[|\]$/g, "");
const isIpLiteral = (h: string) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || h.includes(":");

function normHost(candidate: string): string | null {
  try {
    const h = new URL(`http://${candidate}`).hostname;
    return h ? bare(h) : null;
  } catch {
    return null;
  }
}

function urlHosts(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(AUTHORITY)) {
    const h = normHost(m[1]);
    if (h) out.push(h);
  }
  return out;
}

function bareIpv4(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(IPV4)) {
    if (m[0].split(".").every((o) => Number(o) <= 255)) out.push(m[0]);
  }
  return out;
}

/** Bare targets of network commands, and whether a target is built at runtime. */
function segmentTargets(text: string): { hosts: string[]; unresolved: boolean } {
  const hosts: string[] = [];
  let unresolved = false;
  for (const m of text.matchAll(TARGET_SEGMENT)) {
    const seg = m[1];
    let found = urlHosts(seg).length > 0;
    for (let tok of seg.split(/[\s"'`=,;|&<>()]+/)) {
      if (!tok || tok.startsWith("-") || tok.includes("://") || tok.includes("$")) continue;
      tok = tok.slice(tok.lastIndexOf("@") + 1).toLowerCase();
      let host: string | null = null;
      if (/^\[?[0-9a-f:.]+\]?(?::\d+)?$/.test(tok) && (tok.match(/:/g)?.length ?? 0) >= 2) {
        host = normHost(`[${bare(tok.replace(/\]:\d+$/, "]"))}]`);
      } else {
        if (/^[./~]/.test(tok)) continue; // local path
        const candidate = tok.split("/")[0].split(":")[0]; // host/path, host:path, host:port
        const last = candidate.split(".").pop() ?? "";
        if (NUMERIC_HOST.test(candidate) || (DOMAIN.test(candidate) && !FILE_EXTENSIONS.has(last))) {
          host = normHost(candidate);
        }
      }
      if (host) {
        hosts.push(host);
        found = true;
      }
    }
    if (!found && /[$`]/.test(seg)) unresolved = true;
  }
  return { hosts, unresolved };
}

const UNTRUSTED_BLOCKS = new Set(["image", "document", "image_url"]);

export function buildRequestPolicy(conv: Conversation, allowed: string[], trustToolResults: boolean): RequestPolicy {
  const declared = new Set<string>();
  for (const t of conv.tools) {
    if (!isObject(t)) continue;
    const name = isObject(t.function) ? t.function.name : t.name;
    if (typeof name === "string") declared.add(name);
    // Anthropic toolsets (computer_toolset_*, browser_toolset_*) have no name; members arrive as "<toolset>:<name>".
    const toolset = typeof t.type === "string" ? /^([a-z]+)_toolset_\d{8}$/.exec(t.type) : null;
    if (toolset) declared.add(`${toolset[1]}:*`);
  }

  const out: string[] = [];
  walkStrings(conv.system, out);
  if (trustToolResults) walkStrings(conv.tools, out);
  for (const m of conv.messages) {
    if (m.role === "assistant") continue;
    if (m.role === "tool") {
      if (trustToolResults) walkStrings(m.content, out);
    } else if (typeof m.content === "string") {
      out.push(m.content);
    } else {
      for (const b of m.blocks) {
        if (UNTRUSTED_BLOCKS.has(b.type) || (b.type === "tool_result" && !trustToolResults)) continue;
        walkStrings(b, out);
      }
    }
  }
  const ctxText = out.join("\n").toLowerCase();
  const ctxHosts = new Set([...urlHosts(ctxText), ...bareIpv4(ctxText)]);
  return { declared, ctxText, ctxHosts, allowed: allowed.map((h) => bare(h.toLowerCase())) };
}

function mentioned(host: string, ctx: string): boolean {
  const esc = host.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?<![a-z0-9.-])${esc}(?![a-z0-9-]|\\.[a-z0-9])`).test(ctx);
}

function trusted(host: string, p: RequestPolicy): boolean {
  const h = bare(host);
  return p.allowed.some((a) => h === a || h.endsWith(`.${a}`)) || p.ctxHosts.has(h) || mentioned(h, p.ctxText);
}

export function checkPolicy(name: string, args: string, p: RequestPolicy): PolicyResult {
  const text = callText(args);
  if (SELF_PROTECT_PATTERN.test(text)) {
    return { action: "block", ruleId: "STAGE1-SELF-PROTECT", reason: "call touches the proxy's own configuration" };
  }
  const toolsetMember = name.includes(":") && p.declared.has(`${name.split(":")[0]}:*`);
  if (!p.declared.has(name) && !toolsetMember) {
    return { action: "block", ruleId: "STAGE1-UNDECLARED-TOOL", reason: "undeclared tool" };
  }
  const networkTool = NETWORK_TOOL_PATTERN.test(name);
  if (!networkTool && !NETWORK_PATTERN.test(text)) return { action: "pass" };

  // A URL's host counts anywhere in a reaching call; a bare IP only on a line that reaches out.
  const reaching = networkTool
    ? text
    : text
        .split("\n")
        .filter((l) => NETWORK_PATTERN.test(l))
        .join("\n");
  const targets = segmentTargets(reaching);
  const hosts = new Set<string>([
    ...urlHosts(text).filter((h) => networkTool || !isIpLiteral(h)),
    ...urlHosts(reaching),
    ...bareIpv4(reaching),
    ...targets.hosts,
  ]);
  for (const host of [...hosts].sort()) {
    if (!trusted(host, p)) {
      return {
        action: "block",
        ruleId: "STAGE1-UNTRUSTED-HOST",
        reason: `host \`${host}\` appears nowhere in the trusted conversation`,
      };
    }
  }
  if (targets.unresolved) {
    return { action: "suspicious", ruleId: "STAGE1-UNRESOLVED-TARGET", reason: "network target is built at runtime" };
  }
  return { action: "pass" };
}
