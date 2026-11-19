/**
 * Pass-through recorder for the parity corpus (§9.2): appends `{provider, request, calls}` per guarded
 * request to JSONL (never headers). Scrub with scripts/record-finish.ts before committing.
 *
 *   node scripts/record.ts <targetBase> <out.jsonl> [port]
 *   ANTHROPIC_BASE_URL=http://localhost:8791 claude --bare -p "…"
 */
import { appendFileSync } from "node:fs";
import { createServer } from "node:http";
import { Readable } from "node:stream";
import { sseData } from "../src/sse.ts";

const [TARGET, OUT, PORT = "8791"] = process.argv.slice(2);
if (!TARGET || !OUT) {
  console.error("usage: record.ts <targetBase> <out.jsonl> [port]");
  process.exit(2);
}
const HOP = new Set(["host", "connection", "content-length", "transfer-encoding", "accept-encoding"]);

function anthropicCalls(text: string, json: boolean) {
  const calls: Array<{ name: string; args: string }> = [];
  if (json) {
    for (const b of JSON.parse(text)?.content ?? [])
      if (b?.type === "tool_use") calls.push({ name: b.name, args: JSON.stringify(b.input ?? {}) });
    return calls;
  }
  const held = new Map<number, { name: string; args: string }>();
  for (const ev of sseData(text) as any[]) {
    if (!ev || typeof ev !== "object") continue;
    if (ev.type === "content_block_start" && ev.content_block?.type === "tool_use") {
      const start = ev.content_block.input;
      held.set(ev.index, {
        name: ev.content_block.name,
        args: start && Object.keys(start).length ? JSON.stringify(start) : "",
      });
    } else if (ev.type === "content_block_delta" && held.has(ev.index) && typeof ev.delta?.partial_json === "string") {
      held.get(ev.index)!.args += ev.delta.partial_json;
    } else if (ev.type === "content_block_stop" && held.has(ev.index)) {
      const c = held.get(ev.index)!;
      calls.push({ name: c.name, args: c.args || "{}" });
      held.delete(ev.index);
    }
  }
  return calls;
}

createServer(async (req, res) => {
  let body = Buffer.alloc(0);
  for await (const chunk of req) body = Buffer.concat([body, chunk as Buffer]);
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k) && typeof v === "string") headers.set(k, v);
  const upstream = await fetch(TARGET + req.url, {
    method: req.method,
    headers,
    body: req.method === "GET" || req.method === "HEAD" ? undefined : body,
  });
  const out: Record<string, string> = {};
  upstream.headers.forEach((v, k) => {
    if (!["content-length", "content-encoding", "transfer-encoding", "connection"].includes(k)) out[k] = v;
  });
  res.writeHead(upstream.status, out);
  const guarded = req.method === "POST" && /^\/v1\/messages(?:\?|$)/.test(req.url ?? "");
  let captured = "";
  if (upstream.body) {
    for await (const chunk of Readable.fromWeb(upstream.body as any)) {
      res.write(chunk);
      if (guarded) captured += Buffer.from(chunk).toString("utf8");
    }
  }
  res.end();
  if (guarded && upstream.ok) {
    try {
      const request = JSON.parse(body.toString("utf8"));
      const json = (upstream.headers.get("content-type") ?? "").includes("application/json");
      appendFileSync(
        OUT,
        JSON.stringify({ provider: "anthropic", request, calls: anthropicCalls(captured, json) }) + "\n",
      );
    } catch (e) {
      console.error("record failed", String(e));
    }
  }
}).listen(Number(PORT), "127.0.0.1", () => console.log(`recording ${TARGET} on http://127.0.0.1:${PORT} → ${OUT}`));
