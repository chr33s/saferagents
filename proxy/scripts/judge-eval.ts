/**
 * Live judge accuracy, stability, latency and p(block) margins against Workers AI (§3.5, §9.5).
 * Without CLOUDFLARE_API_TOKEN it uses the remote AI binding via getPlatformProxy (`wrangler login`).
 * Exits non-zero below 100% accuracy.
 *
 *   CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_API_TOKEN=... \
 *     node scripts/judge-eval.ts [model=@cf/cloudflare/clef-flash] [runs=2] [cases.json]
 */
import { readFileSync } from "node:fs";
import { loadConfig } from "../src/config.ts";
import { runJudge } from "../src/judge.ts";
import { pct } from "./stats.ts";

const MODEL = process.argv[2] ?? "@cf/cloudflare/clef-flash";
const RUNS = Number(process.argv[3] ?? 2);
const CASES_PATH = process.argv[4] ?? new URL("../test/fixtures/judge-cases.json", import.meta.url).pathname;
const ACCOUNT = process.env.CLOUDFLARE_ACCOUNT_ID;
const TOKEN = process.env.CLOUDFLARE_API_TOKEN;

type Case = { id: string; expect: "allow" | "block"; task: string; tool: string; args: unknown; findings: any[] };
const cases: Case[] = JSON.parse(readFileSync(CASES_PATH, "utf8"));

// The Workers AI binding's run(model, input), over REST when an API token is set.
const restAI = {
  async run(model: string, input: unknown) {
    const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/ai/run/${model}`, {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify(input),
    });
    const body: any = await res.json();
    if (!res.ok || body?.success === false) throw new Error(`${res.status} ${JSON.stringify(body?.errors ?? body)}`);
    return body.result;
  },
};

async function platformAI() {
  const { getPlatformProxy } = await import("wrangler");
  const configPath = new URL("../wrangler.jsonc", import.meta.url).pathname;
  const proxy = await getPlatformProxy<{ AI: { run(model: string, input: unknown): Promise<unknown> } }>({
    configPath,
    remoteBindings: true,
  } as any);
  return { ai: proxy.env.AI, dispose: () => proxy.dispose() };
}

const platform = TOKEN && ACCOUNT ? null : await platformAI();
const ai = platform?.ai ?? restAI;

const cfg = loadConfig({
  UPSTREAM_ANTHROPIC_URL: "https://api.anthropic.com",
  UPSTREAM_OPENAI_URL: "https://api.openai.com",
  JUDGE_MODEL: MODEL,
  AI: ai,
  ...(process.env.JUDGE_BLOCK_THRESHOLD ? { JUDGE_BLOCK_THRESHOLD: process.env.JUDGE_BLOCK_THRESHOLD } : {}),
});

async function main() {
  const verdicts: Record<string, string[]> = {};
  const latencies: number[] = [];
  const margins: Record<string, number[]> = { block: [], allow: [] };
  const probs: Array<{ expect: string; p: number }> = [];
  let allCorrect = true;
  for (let run = 1; run <= RUNS; run++) {
    let correct = 0;
    for (const c of cases) {
      const t0 = performance.now();
      let verdict: string;
      try {
        const r = await runJudge(ai, cfg, c.task, c.tool, JSON.stringify(c.args), c.findings);
        verdict = r.verdict;
        const p = /p\(block\)=([\d.]+)/.exec(r.reason)?.[1];
        if (p && run === 1) {
          margins[c.expect].push(Number(p));
          probs.push({ expect: c.expect, p: Number(p) });
        }
      } catch (e) {
        verdict = `error: ${e}`;
      }
      latencies.push(performance.now() - t0);
      (verdicts[c.id] ??= []).push(verdict);
      if (verdict === c.expect) correct++;
      else console.log(`run ${run} MISS ${c.id}: expected ${c.expect}, got ${verdict}`);
    }
    console.log(`run ${run}: ${correct}/${cases.length}`);
    if (correct !== cases.length) allCorrect = false;
  }
  const stable = Object.values(verdicts).every((v) => v.every((x) => x === v[0]));
  console.log(
    `model ${MODEL}; verdicts stable: ${stable}; latency p50 ${pct(latencies, 50).toFixed(0)} ms / p90 ${pct(latencies, 90).toFixed(0)} ms`,
  );
  if (margins.block.length) {
    const range = (xs: number[]) => `${Math.min(...xs).toFixed(2)}–${Math.max(...xs).toFixed(2)}`;
    console.log(
      `p(block): block cases ${range(margins.block)}, allow cases ${range(margins.allow)}; threshold ${cfg.judgeBlockThreshold}`,
    );
    // Threshold sweep over run 1's candidate JUDGE_BLOCK_THRESHOLD values.
    for (let t = 0.3; t <= 0.701; t += 0.05) {
      const missedBlocks = probs.filter((x) => x.expect === "block" && x.p < t).length;
      const falseBlocks = probs.filter((x) => x.expect === "allow" && x.p >= t).length;
      console.log(
        `  threshold ${t.toFixed(2)}: ${probs.length - missedBlocks - falseBlocks}/${probs.length} (missed blocks ${missedBlocks}, false blocks ${falseBlocks})`,
      );
    }
  }
  await platform?.dispose();
  process.exit(allCorrect && stable ? 0 : 1);
}

main();
