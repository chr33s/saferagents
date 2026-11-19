import { anthropic } from "./anthropic.ts";
import { audit } from "./audit.ts";
import { loadConfig } from "./config.ts";
import { isObject, parseConversation } from "./conversation.ts";
import { Guard } from "./guard.ts";
import { openai } from "./openai.ts";
import { buildRequestPolicy } from "./policy.ts";
import type { Env, Provider } from "./types.ts";

interface Route {
  method: "GET" | "POST";
  path: string;
  provider: Provider;
  guarded: boolean;
}

const ROUTES: Record<string, Route> = Object.fromEntries(
  [
    { method: "POST", prefix: "/anthropic", path: "/v1/messages", provider: anthropic, guarded: true },
    { method: "POST", prefix: "/anthropic", path: "/v1/messages/count_tokens", provider: anthropic, guarded: false },
    { method: "GET", prefix: "/anthropic", path: "/v1/models", provider: anthropic, guarded: false },
    { method: "POST", prefix: "/openai", path: "/v1/chat/completions", provider: openai, guarded: true },
    { method: "GET", prefix: "/openai", path: "/v1/models", provider: openai, guarded: false },
  ].map(({ prefix, ...r }) => [`${r.method} ${prefix}${r.path}`, r as Route]),
);

const DROP_REQUEST_HEADERS = new Set([
  "host",
  "content-length",
  "connection",
  "transfer-encoding",
  "x-saferagents-key",
  "x-real-ip",
]);

const text = (status: number, msg: string) => new Response(msg, { status, headers: { "content-type": "text/plain" } });

async function tokenMatches(given: string | null, expected: string): Promise<boolean> {
  if (given === null) return false;
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(given)),
    crypto.subtle.digest("SHA-256", enc.encode(expected)),
  ]);
  return crypto.subtle.timingSafeEqual(a, b);
}

function upstreamHeaders(h: Headers): Headers {
  const out = new Headers();
  for (const [k, v] of h) {
    if (!DROP_REQUEST_HEADERS.has(k) && !k.startsWith("cf-") && !k.startsWith("x-forwarded-")) out.set(k, v);
  }
  return out;
}

function responseHeaders(h: Headers): Headers {
  const out = new Headers(h);
  out.delete("content-length");
  out.delete("content-encoding");
  return out;
}

async function guardedResponse(upstream: Response, provider: Provider, guard: Guard): Promise<Response> {
  const contentType = upstream.headers.get("content-type") ?? "";
  const init = { status: upstream.status, headers: responseHeaders(upstream.headers) };
  if (contentType.includes("text/event-stream"))
    return new Response(upstream.body!.pipeThrough(provider.stream(guard)), init);
  if (!contentType.includes("application/json")) return text(502, "saferagents: unexpected upstream content-type");
  const raw = await upstream.text();
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return text(502, "saferagents: upstream returned invalid JSON");
  }
  const changed = isObject(json) && (await provider.guardJson(json, guard));
  return new Response(changed ? JSON.stringify(json) : raw, init);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    let cfg;
    try {
      cfg = loadConfig(env as unknown as Record<string, unknown>);
    } catch (e) {
      console.error("saferagents config error", String(e));
      return text(500, "saferagents: invalid configuration");
    }
    if (!env.PROXY_AUTH_TOKEN) return text(500, "saferagents: PROXY_AUTH_TOKEN is not configured");
    if (!(await tokenMatches(request.headers.get("x-saferagents-key"), env.PROXY_AUTH_TOKEN))) {
      return text(401, "Unauthorized");
    }

    const url = new URL(request.url);
    const route = ROUTES[`${request.method} ${url.pathname}`];
    if (!route) return text(404, "saferagents: route not allowed");
    const upstreamUrl = `${route.provider.upstreamUrl(env)}${route.path}${url.search}`;
    const headers = upstreamHeaders(request.headers);
    if (!route.guarded) {
      return fetch(upstreamUrl, {
        method: route.method,
        headers,
        body: route.method === "GET" ? undefined : request.body,
      });
    }

    // Forward the original bytes; decode only for inspection.
    const bodyBytes = await request.arrayBuffer();
    let body: unknown;
    try {
      body = JSON.parse(new TextDecoder().decode(bodyBytes));
    } catch {
      return text(400, "saferagents: request body must be JSON");
    }
    if (!isObject(body) || Array.isArray(body)) return text(400, "saferagents: request body must be a JSON object");
    const conv = parseConversation(body);
    const rejected = route.provider.reject?.(conv, cfg);
    if (rejected) return text(400, `saferagents: ${rejected}`);

    let upstream: Response;
    try {
      upstream = await fetch(upstreamUrl, { method: "POST", headers, body: bodyBytes });
    } catch {
      return text(502, "saferagents: upstream unreachable");
    }
    if (!upstream.ok || !upstream.body) return upstream;

    // Only the session id is read from headers: credentials never reach the guard (§8.1).
    const sessionId = request.headers.get("x-session-id") ?? "";
    const policy = buildRequestPolicy(conv, cfg.allowedHosts, cfg.trustToolResults);
    const guard = new Guard(conv, policy, cfg, env, (rec) => audit(ctx, env, sessionId, conv, rec));
    return guardedResponse(upstream, route.provider, guard);
  },
};
