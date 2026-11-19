# saferagents

Hugging Face's [`safeagents`](https://github.com/huggingface/safeagents) tool-call guard, run on Cloudflare's edge. It proxies a coding-agent harness (Claude Code, OpenCode, Pi, Codex) to the Anthropic Messages or OpenAI Chat Completions API, holds each tool call until its arguments are complete, then releases it byte for byte or replaces it with a text notice. Design and validation: [`spec.md`](spec.md).

| Worker | Path | Role |
|---|---|---|
| `saferagents-proxy` (TypeScript) | [`proxy/`](proxy) | Auth, routing, SSE guard, Stage 0/1 policy, ATIF trace, judge, audit |
| `saferagents-scanner` (Python/Pyodide) | [`scanner/`](scanner) | Vendored atif-scan 0.8.23 plus gap-fill detectors, over Service Binding RPC |

## Develop

Node, Python and uv are pinned in [`mise.toml`](mise.toml).

```bash
mise install && mise run install
mise run lint      # oxlint, oxfmt --check, tsrs (proxy); ruff (scanner)
mise run format    # oxfmt (proxy); ruff (scanner)
mise run test      # vitest in workerd (proxy); pytest incl. parity (scanner)
```

Parity tests (`scanner/test/test_parity.py`, spec §9.2) compare against upstream `safeagents` pinned at `dcf38e0`, over recorded Claude Code requests in `scanner/test/recorded/` plus a seeded synthetic corpus. Record more with `proxy/scripts/record.ts` and scrub them with `proxy/scripts/record-finish.ts`.

### e2e and budgets (spec §9.4)

```bash
(cd scanner && uv run pywrangler dev --port 8788)
(cd proxy && node scripts/mock-upstream.ts 8790)
(cd proxy && npx wrangler dev --port 8787 --var ALLOW_CUSTOM_UPSTREAM:true \
   --var UPSTREAM_ANTHROPIC_URL:http://localhost:8790 --var UPSTREAM_OPENAI_URL:http://localhost:8790 \
   --var PROXY_AUTH_TOKEN:dev-token --var ENABLE_JUDGE:false)
(cd proxy && npm run e2e)          # verdict per scenario + added release latency
(cd proxy && npm run bench:cpu)    # local approximation of proxy CPU
(cd proxy && npm run judge:eval)   # live judge regression set (wrangler login or CLOUDFLARE_API_TOKEN)
```

## Deploy (spec §8)

```bash
(cd scanner && uv run pywrangler deploy)            # plain wrangler fails: No module named 'workers'
cd proxy
npx wrangler r2 bucket create saferagents-traces
npx wrangler r2 bucket lifecycle add saferagents-traces expire-30d --expire-days 30
openssl rand -base64 32 | npx wrangler secret put PROXY_AUTH_TOKEN
npx wrangler deploy
```

Point the harness at the proxy:

```bash
export ANTHROPIC_BASE_URL="https://saferagents-proxy.<subdomain>.workers.dev/anthropic"
export ANTHROPIC_CUSTOM_HEADERS="x-saferagents-key: <token>"
```

OpenAI-compatible harnesses use `https://saferagents-proxy.<subdomain>.workers.dev/openai/v1` with the same header. Configuration lives in `proxy/wrangler.jsonc` (`vars`); every default fails closed (spec §3.4). Workers Paid is required. Credential policy: spec §8.1.
