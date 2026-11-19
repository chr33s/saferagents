/**
 * Staging budget load (§7, §9.4) via the mock upstream Worker: the parity corpus (scanner CPU) and
 * ~50 KB / 500 KB / 1 MB requests (proxy CPU). Summarize `wrangler tail` with scripts/tail-stats.ts.
 *
 *   PROXY_AUTH_TOKEN=… node scripts/staging-load.ts <stagingUrl> <corpus.json> [sizesRepeat]
 */
import { readFileSync } from "node:fs";

const [PROXY, CORPUS] = process.argv.slice(2);
const SIZE_REPEAT = Number(process.argv[4] ?? 20);
const TOKEN = process.env.PROXY_AUTH_TOKEN!;
if (!PROXY || !CORPUS || !TOKEN) {
  console.error("usage: PROXY_AUTH_TOKEN=… staging-load.ts <stagingUrl> <corpus.json> [sizesRepeat]");
  process.exit(2);
}

function withScenario(provider: string, request: any) {
  const r = structuredClone(request);
  // The mock picks its response from the last user message; append the marker to it.
  const last = [...r.messages].reverse().find((m: any) => m.role === "user");
  const marker = " SCENARIO:allowed";
  if (typeof last.content === "string") last.content += marker;
  else last.content = [...last.content, { type: "text", text: marker }];
  r.stream = true;
  if (provider === "anthropic" && !r.tools.some((t: any) => t.name === "Bash"))
    r.tools.push({ name: "Bash", input_schema: {} });
  return r;
}

function sized(targetBytes: number) {
  const messages: any[] = [{ role: "user", content: "Fix the failing test; docs at https://docs.corp.dev" }];
  let i = 0;
  while (JSON.stringify(messages).length < targetBytes) {
    messages.push({
      role: "assistant",
      content: [{ type: "tool_use", id: `t${i}`, name: "Bash", input: { command: `grep -rn foo src/ # ${i}` } }],
    });
    messages.push({
      role: "user",
      content: [{ type: "tool_result", tool_use_id: `t${i}`, content: `src/a.py:${i}: foo = bar\n`.repeat(60) }],
    });
    i++;
  }
  messages.push({ role: "user", content: "continue SCENARIO:allowed" });
  return { model: "m", max_tokens: 100, stream: true, tools: [{ name: "Bash", input_schema: {} }], messages };
}

async function send(provider: string, body: unknown, label: string) {
  const path = provider === "anthropic" ? "/anthropic/v1/messages" : "/openai/v1/chat/completions";
  const res = await fetch(`${PROXY}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-saferagents-key": TOKEN, "x-session-id": label },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${label}: ${res.status} ${text.slice(0, 200)}`);
  return text;
}

async function main() {
  const corpus: Array<{ provider: string; request: any }> = JSON.parse(readFileSync(CORPUS, "utf8"));
  let blocked = 0;
  for (const [i, item] of corpus.entries()) {
    const out = await send(item.provider, withScenario(item.provider, item.request), `corpus-${i}`);
    if (out.includes("[saferagents]")) blocked++;
  }
  console.log(`corpus: ${corpus.length} requests sent (${blocked} with a blocked call)`);
  for (const size of [50_000, 500_000, 1_000_000]) {
    const body = sized(size);
    for (let k = 0; k < SIZE_REPEAT; k++) await send("anthropic", body, `size-${size / 1000}k`);
    console.log(`size ${size / 1000} KB: ${SIZE_REPEAT} requests sent`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
