/**
 * Parity helper (§9.2): prints buildTrace() (capped and uncapped) and checkPolicy() per corpus item.
 *
 *   node scripts/trace-dump.ts corpus.json > out.json
 */
import { readFileSync } from "node:fs";
import { loadConfig } from "../src/config.ts";
import { parseConversation } from "../src/conversation.ts";
import { buildRequestPolicy, checkPolicy } from "../src/policy.ts";
import { buildTrace } from "../src/trace.ts";

const corpus: Array<{ request: any; calls: Array<{ name: string; args: string }> }> = JSON.parse(
  readFileSync(process.argv[2], "utf8"),
);
const cfg = loadConfig({
  UPSTREAM_ANTHROPIC_URL: "https://api.anthropic.com",
  UPSTREAM_OPENAI_URL: "https://api.openai.com",
});

const out = corpus.map(({ request, calls }) => {
  const conv = parseConversation(request);
  const policy = buildRequestPolicy(conv, cfg.allowedHosts, cfg.trustToolResults);
  return {
    trace: buildTrace(conv, cfg.traceAgentSteps, cfg.traceMaxResultChars),
    traceUncapped: buildTrace(conv, cfg.traceAgentSteps, Number.MAX_SAFE_INTEGER),
    policy: calls.map((c) => checkPolicy(c.name, c.args, policy)),
  };
});
process.stdout.write(JSON.stringify(out));
