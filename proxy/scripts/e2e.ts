/**
 * e2e verdict and added-latency driver (§9.4), against local `wrangler dev` and the mock upstream:
 *
 *   (cd scanner && uv run pywrangler dev --port 8788)
 *   node scripts/mock-upstream.ts 8790
 *   npx wrangler dev --port 8787 --var ALLOW_CUSTOM_UPSTREAM:true \
 *     --var UPSTREAM_ANTHROPIC_URL:http://localhost:8790 --var UPSTREAM_OPENAI_URL:http://localhost:8790 \
 *     --var PROXY_AUTH_TOKEN:dev-token --var ENABLE_JUDGE:false
 *   node scripts/e2e.ts [proxyUrl] [iterations]
 */
import { pct } from "./stats.ts";
const PROXY = process.argv[2] ?? "http://localhost:8787";
const ITER = Number(process.argv[3] ?? 20);
const UPSTREAM = process.env.MOCK_UPSTREAM ?? "http://localhost:8790";
const TOKEN = process.env.PROXY_AUTH_TOKEN ?? "dev-token";

const task = (scenario: string) => `Fix the failing test. SCENARIO:${scenario}`;
const NAMES = ["Bash", "Read", "Write", "Edit"];

/** Per API: proxy path, request body, and how a kept (released) call appears in the output. */
const APIS = {
  anthropic: {
    path: "/anthropic/v1/messages",
    body: (s: string) => ({
      model: "mock",
      max_tokens: 100,
      stream: true,
      tools: NAMES.map((name) => ({ name, input_schema: { type: "object" } })),
      messages: [{ role: "user", content: task(s) }],
    }),
    kept: /"type":"tool_use"/g,
  },
  openai: {
    path: "/openai/v1/chat/completions",
    body: (s: string) => ({
      model: "mock",
      stream: true,
      tools: NAMES.map((name) => ({ type: "function", function: { name, parameters: { type: "object" } } })),
      messages: [{ role: "user", content: task(s) }],
    }),
    kept: /"id":"call_\d+"/g,
  },
  "xai-responses": {
    path: "/xai/v1/responses",
    body: (s: string) => ({
      model: "mock",
      stream: true,
      tools: NAMES.map((name) => ({ type: "function", name, parameters: { type: "object" } })),
      input: [{ role: "user", content: task(s) }],
    }),
    kept: /"type":"response\.output_item\.done"[^\n]*"type":"function_call"/g,
  },
  gemini: {
    path: "/gemini/v1beta/models/mock:streamGenerateContent?alt=sse",
    body: (s: string) => ({
      tools: [{ functionDeclarations: NAMES.map((name) => ({ name, parameters: { type: "object" } })) }],
      contents: [{ role: "user", parts: [{ text: task(s) }] }],
    }),
    kept: /"functionCall"/g,
  },
} as const;
type Api = keyof typeof APIS;

type Expect = { blocked: string[]; kept: number };
const SCENARIOS: Array<{ scenario: string; expect: Expect }> = [
  { scenario: "text", expect: { blocked: [], kept: 0 } },
  { scenario: "allowed", expect: { blocked: [], kept: 1 } },
  { scenario: "untrusted-host", expect: { blocked: ["STAGE1-UNTRUSTED-HOST"], kept: 0 } },
  { scenario: "env-exfil", expect: { blocked: ["saferagents.env_exfil"], kept: 0 } },
  { scenario: "credential-read", expect: { blocked: ["saferagents.credential_store"], kept: 0 } },
  { scenario: "reverse-shell", expect: { blocked: ["STAGE1-UNTRUSTED-HOST"], kept: 0 } },
  { scenario: "conftest", expect: { blocked: ["tamper.harness_hooks"], kept: 0 } },
  { scenario: "parallel", expect: { blocked: ["saferagents.credential_store"], kept: 2 } },
];

async function run(base: string, api: Api, scenario: string, id: string, viaProxy: boolean) {
  const path = APIS[api].path;
  const url = viaProxy ? `${base}${path}` : `${base}${path.replace(/^\/[a-z]+/, "")}`;
  const t0 = performance.timeOrigin + performance.now();
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-saferagents-key": TOKEN,
      "x-mock-request-id": id,
      "x-session-id": "e2e",
    },
    body: JSON.stringify(APIS[api].body(scenario)),
  });
  if (!res.ok || !res.body) throw new Error(`${url}: ${res.status} ${await res.text()}`);
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let text = "";
  let firstByte = 0;
  let stopReasonAt = 0;
  const toolSeen: number[] = [];
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    const now = performance.timeOrigin + performance.now();
    if (!firstByte) firstByte = now;
    const before = text;
    text += value;
    // Release = Anthropic content_block_stop / OpenAI tool_calls chunk, or a [saferagents] notice.
    const fresh = text.slice(before.length);
    const releases =
      api === "anthropic"
        ? (fresh.match(/"type":"tool_use"|\[saferagents\]/g) ?? []).length
        : (fresh.match(/"tool_calls":\[\{|\[saferagents\]/g) ?? []).length;
    for (let i = 0; i < releases; i++) toolSeen.push(now);
    if (!stopReasonAt && /"stop_reason":"tool_use"|"finish_reason":"tool_calls"/.test(fresh)) stopReasonAt = now - t0;
  }
  return { text, ttfb: firstByte - t0, toolSeen, stopReasonAt };
}

async function main() {
  let failures = 0;
  console.log(`verdicts via ${PROXY}`);
  for (const api of Object.keys(APIS) as Api[]) {
    for (const c of SCENARIOS) {
      const { text } = await run(PROXY, api, c.scenario, `v-${api}-${c.scenario}`, true);
      const notices = [...new Set(text.match(/\[saferagents\] blocked call to `[^`]+`: [^"\\]*/g) ?? [])];
      const kept = (text.match(APIS[api].kept) ?? []).length;
      const ok =
        kept === c.expect.kept &&
        c.expect.blocked.every((rule) => notices.some((n) => n.includes(rule))) &&
        notices.length === c.expect.blocked.length;
      if (!ok) failures++;
      console.log(`${ok ? "PASS" : "FAIL"} ${api}/${c.scenario}: kept=${kept} notices=${JSON.stringify(notices)}`);
    }
  }

  const added: number[] = [];
  const ttfbProxy: number[] = [];
  const ttfbDirect: number[] = [];
  const timingsAvailable = await fetch(`${UPSTREAM}/__timings`).then(
    (r) => r.ok && (r.headers.get("content-type") ?? "").includes("json"),
    () => false,
  );
  for (let i = 0; i < ITER; i++) {
    const id = `lat-${i}`;
    const r = await run(PROXY, "anthropic", "allowed", id, true);
    ttfbProxy.push(r.ttfb);
    const d = await run(UPSTREAM, "anthropic", "allowed", `d-${i}`, false);
    ttfbDirect.push(d.ttfb);
    if (timingsAvailable) {
      // Local mock: exact gap from the mock's last tool frame to the client receiving the release.
      const t = (await (await fetch(`${UPSTREAM}/__timings`)).json()) as Record<string, { toolStopAt: number[] }>;
      const stop = t[id]?.toolStopAt[0];
      if (stop && r.toolSeen[0]) added.push(r.toolSeen[0] - stop);
    } else if (r.stopReasonAt && d.stopReasonAt) {
      // Remote mock: stop_reason directly follows the last tool frame, so proxy-vs-direct arrival ≈ added latency.
      added.push(r.stopReasonAt - d.stopReasonAt);
    }
  }
  console.log(
    `\nadded latency before tool release (warm, no judge): p50 ${pct(added, 50).toFixed(0)} ms, p95 ${pct(added, 95).toFixed(0)} ms (budget p95 <= 500 ms)`,
  );
  console.log(
    `time to first byte: proxy p50 ${pct(ttfbProxy, 50).toFixed(0)} ms vs direct p50 ${pct(ttfbDirect, 50).toFixed(0)} ms`,
  );
  if (pct(added, 95) > 500) failures++;
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
