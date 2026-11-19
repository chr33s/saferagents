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

const TOOLS = ["Bash", "Read", "Write", "Edit"].map((name) => ({ name, input_schema: { type: "object" } }));
const OPENAI_TOOLS = ["Bash", "Read", "Write"].map((name) => ({
  type: "function",
  function: { name, parameters: { type: "object" } },
}));

type Expect = { blocked: string[]; kept: number };
const CASES: Array<{ scenario: string; provider: "anthropic" | "openai"; expect: Expect }> = [
  { scenario: "text", provider: "anthropic", expect: { blocked: [], kept: 0 } },
  { scenario: "allowed", provider: "anthropic", expect: { blocked: [], kept: 1 } },
  { scenario: "untrusted-host", provider: "anthropic", expect: { blocked: ["STAGE1-UNTRUSTED-HOST"], kept: 0 } },
  { scenario: "env-exfil", provider: "anthropic", expect: { blocked: ["saferagents.env_exfil"], kept: 0 } },
  {
    scenario: "credential-read",
    provider: "anthropic",
    expect: { blocked: ["saferagents.credential_store"], kept: 0 },
  },
  { scenario: "reverse-shell", provider: "anthropic", expect: { blocked: ["STAGE1-UNTRUSTED-HOST"], kept: 0 } },
  { scenario: "conftest", provider: "anthropic", expect: { blocked: ["tamper.harness_hooks"], kept: 0 } },
  { scenario: "parallel", provider: "anthropic", expect: { blocked: ["saferagents.credential_store"], kept: 2 } },
  { scenario: "allowed", provider: "openai", expect: { blocked: [], kept: 1 } },
  { scenario: "env-exfil", provider: "openai", expect: { blocked: ["saferagents.env_exfil"], kept: 0 } },
];

function body(provider: "anthropic" | "openai", scenario: string) {
  const messages = [{ role: "user", content: `Fix the failing test. SCENARIO:${scenario}` }];
  return provider === "anthropic"
    ? { model: "mock", max_tokens: 100, stream: true, tools: TOOLS, messages }
    : { model: "mock", stream: true, tools: OPENAI_TOOLS, messages };
}

async function run(base: string, provider: "anthropic" | "openai", scenario: string, id: string, viaProxy: boolean) {
  const path = provider === "anthropic" ? "/v1/messages" : "/v1/chat/completions";
  const url = viaProxy ? `${base}/${provider}${path}` : `${base}${path}`;
  const t0 = performance.timeOrigin + performance.now();
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-saferagents-key": TOKEN,
      "x-mock-request-id": id,
      "x-session-id": "e2e",
    },
    body: JSON.stringify(body(provider, scenario)),
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
      provider === "anthropic"
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
  for (const c of CASES) {
    const { text } = await run(PROXY, c.provider, c.scenario, `v-${c.provider}-${c.scenario}`, true);
    const notices = text.match(/\[saferagents\] blocked call to `[^`]+`: [^"\\]*/g) ?? [];
    const kept =
      c.provider === "anthropic"
        ? (text.match(/"type":"tool_use"/g) ?? []).length
        : (text.match(/"id":"call_\d+"/g) ?? []).length;
    const ok =
      kept === c.expect.kept &&
      c.expect.blocked.every((rule) => notices.some((n) => n.includes(rule))) &&
      notices.length === c.expect.blocked.length;
    if (!ok) failures++;
    console.log(`${ok ? "PASS" : "FAIL"} ${c.provider}/${c.scenario}: kept=${kept} notices=${JSON.stringify(notices)}`);
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
