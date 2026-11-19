// One R2 object per non-passed call. Never headers; arguments and task are scrubbed and truncated.
import type { Conversation } from "./conversation.ts";
import type { AuditRecord } from "./guard.ts";
import { taskText } from "./judge.ts";
import { scrub } from "./scrub.ts";
import type { Env } from "./types.ts";

export function audit(ctx: ExecutionContext, env: Env, sessionId: string, conv: Conversation, rec: AuditRecord): void {
  console.warn(
    `[saferagents] ${rec.verdict} call to ${rec.tool}: ${rec.reason ?? rec.findings.map((f) => f.ruleId).join(", ")}`,
  );
  if (!env.TRACE_BUCKET) return;
  const session = sessionId.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 64) || "anon";
  const now = new Date();
  const key = `traces/${now.toISOString().slice(0, 10)}/${session}/${now.getTime()}-${crypto.randomUUID()}.json`;
  const record = {
    time: now.toISOString(),
    model: conv.model,
    verdict: rec.verdict,
    tool: rec.tool,
    arguments: scrub(rec.arguments).slice(0, 8192),
    reason: rec.reason ?? null,
    findings: rec.findings,
    judge: rec.judge ?? null,
    note: rec.note ? scrub(rec.note).slice(0, 1024) : null,
    task: scrub(taskText(conv)).slice(-2048),
  };
  ctx.waitUntil(
    env.TRACE_BUCKET.put(key, JSON.stringify(record), { httpMetadata: { contentType: "application/json" } })
      .then(() => undefined)
      .catch((e) => console.error("[saferagents] audit write failed", String(e))),
  );
}
