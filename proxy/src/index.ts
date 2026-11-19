import { anthropic } from "./anthropic.ts";
import { audit } from "./audit.ts";
import { loadConfig } from "./config.ts";
import type { Upstream } from "./constants.ts";
import { isObject } from "./conversation.ts";
import { gemini } from "./gemini.ts";
import { Guard } from "./guard.ts";
import { openai } from "./openai.ts";
import { buildRequestPolicy } from "./policy.ts";
import { responses } from "./responses.ts";
import type { Env, Provider } from "./types.ts";

interface Route {
  method: "GET" | "POST";
  /** Matches the proxy path; group 1 is the upstream path. */
  match: RegExp;
  upstream: Upstream;
  /** Guarded routes only. */
  provider?: Provider;
}

const route = (
  method: Route["method"],
  prefix: string,
  path: string | RegExp,
  upstream: Upstream,
  provider?: Provider,
): Route => ({
  method,
  match: new RegExp(
    `^${prefix}(${typeof path === "string" ? path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") : path.source})$`,
  ),
  upstream,
  provider,
});

const GEMINI_MODEL = String.raw`/v1(?:beta)?/models/[\w.-]+`;
const ROUTES: Route[] = [
  route("POST", "/anthropic", "/v1/messages", "anthropic", anthropic),
  route("POST", "/anthropic", "/v1/messages/count_tokens", "anthropic"),
  route("GET", "/anthropic", "/v1/models", "anthropic"),
  route("POST", "/openai", "/v1/chat/completions", "openai", openai),
  route("POST", "/openai", "/v1/responses", "openai", responses),
  route("GET", "/openai", "/v1/models", "openai"),
  route("POST", "/xai", "/v1/chat/completions", "xai", openai),
  route("POST", "/xai", "/v1/responses", "xai", responses),
  route("GET", "/xai", "/v1/models", "xai"),
  route("POST", "/gemini", new RegExp(`${GEMINI_MODEL}:(?:generateContent|streamGenerateContent)`), "gemini", gemini),
  route("POST", "/gemini", new RegExp(`${GEMINI_MODEL}:countTokens`), "gemini"),
  route("GET", "/gemini", /\/v1(?:beta)?\/models(?:\/[\w.-]+)?/, "gemini"),
];

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
    let upstreamPath = "";
    const route = ROUTES.find(
      (r) => r.method === request.method && (upstreamPath = r.match.exec(url.pathname)?.[1] ?? ""),
    );
    if (!route) return text(404, "saferagents: route not allowed");
    const upstreamUrl = `${cfg.upstreams[route.upstream]}${upstreamPath}${url.search}`;
    const headers = upstreamHeaders(request.headers);
    const provider = route.provider;
    if (!provider) {
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
    const conv = provider.parse(body);
    if (cfg.denyServerTools && conv.serverTools.length) {
      return text(
        400,
        `saferagents: server-executed tools are disabled (SERVER_TOOLS=deny): ${conv.serverTools.join(", ")}`,
      );
    }

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
    return guardedResponse(upstream, provider, guard);
  },
};
