import {
  anthropicFrames,
  geminiFrames,
  openaiFrames,
  responsesFrames,
  type FixtureCall,
} from "../scripts/sse-fixtures.ts";
import { loadConfig, type Config } from "../src/config.ts";
import { parseConversation, type Conversation } from "../src/conversation.ts";
import { Guard, type AuditRecord } from "../src/guard.ts";
import { buildRequestPolicy } from "../src/policy.ts";
import { sseData } from "../src/sse.ts";
import type { Env } from "../src/types.ts";

export const OFFICIAL = {
  UPSTREAM_ANTHROPIC_URL: "https://api.anthropic.com",
  UPSTREAM_OPENAI_URL: "https://api.openai.com",
};

export type ScanFn = (request: string) => Promise<string>;

/** A scanner that returns no findings unless `findings` maps a substring of the last call to some. */
export function fakeScanner(
  findings: Record<string, Array<{ ruleId: string; severity: string; title?: string }>> = {},
) {
  const payloads: string[] = [];
  const scan: ScanFn = async (request) => {
    payloads.push(request);
    const req = JSON.parse(request);
    const last = JSON.stringify(req.calls[req.calls.length - 1]);
    for (const [needle, fs] of Object.entries(findings)) {
      if (last.includes(needle)) return JSON.stringify({ findings: fs.map((f) => ({ title: "t", ...f })) });
    }
    return JSON.stringify({ findings: [] });
  };
  return { scan, payloads };
}

export function fakeAI(answer: (model: string, input: any) => any) {
  const calls: Array<{ model: string; input: any }> = [];
  return {
    calls,
    async run(model: string, input: any) {
      calls.push({ model, input });
      return answer(model, input);
    },
  };
}

export function fakeBucket() {
  const puts: Array<{ key: string; value: string }> = [];
  return {
    puts,
    async put(key: string, value: string) {
      puts.push({ key, value });
      return {};
    },
  };
}

export function makeEnv(overrides: Partial<Env> & Record<string, unknown> = {}): Env {
  return {
    ...OFFICIAL,
    PROXY_AUTH_TOKEN: "test-token",
    ATIF_SCANNER: fakeScanner(),
    ENABLE_JUDGE: "false",
    ...overrides,
  } as Env;
}

export function makeCtx() {
  const waits: Promise<unknown>[] = [];
  return {
    waits,
    ctx: {
      waitUntil: (p: Promise<unknown>) => waits.push(p),
      passThroughOnException() {},
      props: {},
    } as unknown as ExecutionContext,
  };
}

export const BASH_TOOL = { name: "Bash", description: "run", input_schema: { type: "object" } };
export const OPENAI_BASH_TOOL = { type: "function", function: { name: "Bash", parameters: { type: "object" } } };

export function anthropicBody(userText = "help me", extra: Record<string, unknown> = {}) {
  return {
    model: "claude-test",
    max_tokens: 100,
    tools: [
      BASH_TOOL,
      { name: "Read", input_schema: { type: "object" } },
      { name: "Write", input_schema: { type: "object" } },
      { name: "WebFetch", input_schema: { type: "object" } },
    ],
    messages: [{ role: "user", content: userText }],
    ...extra,
  };
}

export function openaiBody(userText = "help me", extra: Record<string, unknown> = {}) {
  return {
    model: "gpt-test",
    tools: [OPENAI_BASH_TOOL],
    messages: [{ role: "user", content: userText }],
    ...extra,
  };
}

export function responsesBody(userText = "help me", extra: Record<string, unknown> = {}) {
  return {
    model: "grok-test",
    instructions: "You are a coding agent.",
    tools: [{ type: "function", name: "Bash", parameters: { type: "object" } }, { type: "local_shell" }],
    input: [{ role: "user", content: [{ type: "input_text", text: userText }] }],
    stream: true,
    ...extra,
  };
}

export function geminiBody(userText = "help me", extra: Record<string, unknown> = {}) {
  return {
    systemInstruction: { parts: [{ text: "You are a coding agent." }] },
    tools: [{ functionDeclarations: [{ name: "run_shell_command", parameters: { type: "object" } }] }],
    contents: [{ role: "user", parts: [{ text: userText }] }],
    ...extra,
  };
}

export function makeGuard(
  body: any,
  opts: { env?: Record<string, unknown>; scanner?: ScanFn; ai?: any; parse?: (body: any) => Conversation } = {},
): { guard: Guard; cfg: Config; audits: AuditRecord[] } {
  const envVars = { ...OFFICIAL, ENABLE_JUDGE: "false", ...opts.env, AI: opts.ai };
  const cfg = loadConfig(envVars);
  const conv = (opts.parse ?? parseConversation)(body);
  const policy = buildRequestPolicy(conv, cfg.allowedHosts, cfg.trustToolResults);
  const audits: AuditRecord[] = [];
  const env = { ...envVars, ATIF_SCANNER: { scan: opts.scanner ?? fakeScanner().scan } } as unknown as Env;
  const guard = new Guard(conv, policy, cfg, env, (r) => audits.push(r));
  return { guard, cfg, audits };
}

// ---------- SSE ----------

export { aEvent, oData } from "../scripts/sse-fixtures.ts";

export const anthropicToolStream = (calls: FixtureCall[], opts: { text?: string; stop?: boolean } = {}) =>
  anthropicFrames({ calls, text: opts.text }, opts).map((f) => f.frame);

export const openaiToolStream = (
  calls: FixtureCall[],
  opts: { text?: string; finish?: boolean; done?: boolean } = {},
) => openaiFrames({ calls, text: opts.text }, opts).map((f) => f.frame);

export const responsesToolStream = (calls: FixtureCall[], opts: { text?: string; complete?: boolean } = {}) =>
  responsesFrames({ calls, text: opts.text }, opts).map((f) => f.frame);

export const geminiToolStream = (calls: FixtureCall[], opts: { text?: string } = {}) =>
  geminiFrames({ calls, text: opts.text }).map((f) => f.frame);

/** Runs `chunks` through a byte stream transform and returns the decoded output. */
export async function runStream(t: TransformStream<Uint8Array, Uint8Array>, chunks: string[]): Promise<string> {
  const enc = new TextEncoder();
  const rs = new ReadableStream<Uint8Array>({
    start(c) {
      for (const ch of chunks) c.enqueue(enc.encode(ch));
      c.close();
    },
  });
  return new Response(rs.pipeThrough(t)).text();
}

export const parseSse = (out: string): any[] => sseData(out);
