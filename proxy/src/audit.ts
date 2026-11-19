// Every audited call (non-passed, or passed with a note) gets one scrubbed console line, and one R2 object when a
// bucket is given (AUDIT_MODE, §8.1). Never headers; arguments, task and log text are scrubbed and truncated.
import type { Conversation } from "./conversation.ts";
import type { AuditRecord } from "./guard.ts";
import { taskText } from "./judge.ts";
import { scrub } from "./scrub.ts";

export function audit(
  ctx: ExecutionContext,
  bucket: R2Bucket | undefined,
  sessionId: string,
  conv: Conversation,
  rec: AuditRecord,
): void {
  const detail = [
    rec.reason ?? rec.findings.map((f) => f.ruleId).join(", "),
    rec.judge && `judge: ${rec.judge}`,
    rec.note,
  ]
    .filter(Boolean)
    .join("; ");
  console.warn(`[saferagents] ${rec.verdict} call to ${rec.tool}: ${scrub(detail).slice(0, 300)}`);
  if (!bucket) return;
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
    bucket
      .put(key, JSON.stringify(record), { httpMetadata: { contentType: "application/json" } })
      .then(() => undefined)
      .catch((e) => console.error("[saferagents] audit write failed", String(e))),
  );
}
