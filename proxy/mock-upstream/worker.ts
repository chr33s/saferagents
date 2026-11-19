/**
 * Mock upstream Worker for staging runs (§8 smoke, §9.4 budgets); point a staging proxy at it with
 * ALLOW_CUSTOM_UPSTREAM=true. Never use in production.
 */
import { anthropicFrames, openaiFrames, scenarioOf } from "../scripts/sse-fixtures.ts";

const DEFAULT_FRAME_DELAY_MS = 15;

export default {
  async fetch(request: Request, _env: unknown, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname.endsWith("/v1/models"))
      return Response.json({ data: [{ id: "mock" }] });
    if (request.method !== "POST") return new Response("not found", { status: 404 });
    let body: any = {};
    try {
      body = await request.json();
    } catch {}
    const scenario = scenarioOf(body);
    const delay = Number(request.headers.get("x-mock-frame-delay") ?? DEFAULT_FRAME_DELAY_MS);
    const frames = url.pathname.endsWith("/chat/completions") ? openaiFrames(scenario) : anthropicFrames(scenario);
    if (body?.stream === false) return Response.json({ mock: "non-streaming not modelled" }, { status: 400 });
    const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
    const writer = writable.getWriter();
    const enc = new TextEncoder();
    ctx.waitUntil(
      (async () => {
        for (const f of frames) {
          await writer.write(enc.encode(f.frame));
          if (delay > 0) await new Promise((r) => setTimeout(r, delay));
        }
        await writer.close();
      })(),
    );
    return new Response(readable, { headers: { "content-type": "text/event-stream", "cache-control": "no-cache" } });
  },
};
