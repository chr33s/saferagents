/**
 * Mock Anthropic/OpenAI upstream (§9.4): replays "SCENARIO:<name>" SSE streams with FRAME_DELAY_MS
 * (default 15) between frames and logs each tool block's last-frame time for latency measurement.
 *
 *   node scripts/mock-upstream.ts [port]          # default 8790
 *   GET /__timings  → { [requestId]: { toolStopAt: number[] } }
 */
import { createServer } from "node:http";
import { anthropicFrames, openaiFrames, scenarioOf } from "./sse-fixtures.ts";

const PORT = Number(process.argv[2] ?? 8790);
const FRAME_DELAY_MS = Number(process.env.FRAME_DELAY_MS ?? 15);

const timings: Record<string, { toolStopAt: number[] }> = {};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/__timings") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(timings));
    return;
  }
  if (req.method === "GET" && req.url?.endsWith("/v1/models")) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ data: [{ id: "mock" }] }));
    return;
  }
  let raw = "";
  for await (const chunk of req) raw += chunk;
  let body: any = {};
  try {
    body = JSON.parse(raw);
  } catch {}
  const scenario = scenarioOf(body);
  const requestId = String(req.headers["x-mock-request-id"] ?? Date.now());
  timings[requestId] = { toolStopAt: [] };
  const openai = req.url?.endsWith("/chat/completions") ?? false;
  const frames = openai ? openaiFrames(scenario) : anthropicFrames(scenario);
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  for (const f of frames) {
    res.write(f.frame);
    if (f.toolStop) timings[requestId].toolStopAt.push(performance.timeOrigin + performance.now());
    await sleep(FRAME_DELAY_MS);
  }
  res.end();
}).listen(PORT, () => console.log(`mock upstream on http://localhost:${PORT}`));
