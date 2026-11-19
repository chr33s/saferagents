/**
 * Local V8 approximation of the proxy CPU budget (§7: p95 <= 10 ms up to 100 KB, <= 30 ms up to 1 MB);
 * production numbers come from Workers `cpuTime` on staging.
 *
 *   node scripts/bench-cpu.ts [iterations]
 */
import { loadConfig } from "../src/config.ts";
import { buildRequestPolicy, checkPolicy } from "../src/policy.ts";
import { buildTrace } from "../src/trace.ts";
import { pct } from "./stats.ts";

const ITER = Number(process.argv[2] ?? 200);
const cfg = loadConfig({
  UPSTREAM_ANTHROPIC_URL: "https://api.anthropic.com",
  UPSTREAM_OPENAI_URL: "https://api.openai.com",
});

function request(targetBytes: number): string {
  const messages: any[] = [
    { role: "user", content: "Fix the failing test in tests/test_auth.py; docs at https://docs.corp.dev" },
  ];
  let i = 0;
  while (JSON.stringify(messages).length < targetBytes) {
    messages.push({
      role: "assistant",
      content: [
        { type: "text", text: `step ${i}` },
        { type: "tool_use", id: `t${i}`, name: "Bash", input: { command: `grep -rn foo src/ # ${i}` } },
      ],
    });
    messages.push({
      role: "user",
      content: [
        {
          type: "tool_result",
          tool_use_id: `t${i}`,
          content: `src/a.py:${i}: foo = bar  # see https://x${i}.example.com\n`.repeat(40),
        },
      ],
    });
    i++;
  }
  return JSON.stringify({
    model: "m",
    max_tokens: 1000,
    tools: [{ name: "Bash", input_schema: {} }],
    system: "You are a coding agent.",
    messages,
  });
}

for (const size of [50_000, 500_000, 1_000_000]) {
  const raw = request(size);
  const times: number[] = [];
  for (let k = 0; k < ITER; k++) {
    const t0 = performance.now();
    const body = JSON.parse(raw);
    const policy = buildRequestPolicy(body, cfg.allowedHosts, cfg.trustToolResults);
    buildTrace(body, cfg.traceAgentSteps, cfg.traceMaxResultChars);
    checkPolicy("Bash", JSON.stringify({ command: "curl -fsS https://docs.corp.dev/x && npm test" }), policy);
    times.push(performance.now() - t0);
  }
  console.log(
    `${(raw.length / 1000).toFixed(0).padStart(5)} KB: p50 ${pct(times, 50).toFixed(2)} ms, p95 ${pct(times, 95).toFixed(2)} ms (budget p95 <= ${size <= 100_000 ? 10 : 30} ms)`,
  );
}
