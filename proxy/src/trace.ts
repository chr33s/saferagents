import { contentText, type Conversation } from "./conversation.ts";
import type { AtifStep } from "./types.ts";

/** Upstream _tool_call argument normalization. */
export function atifArguments(args: unknown): Record<string, unknown> {
  let v = args;
  if (typeof v === "string") {
    try {
      v = JSON.parse(v);
    } catch {
      return { input: args as string };
    }
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) return { input: JSON.stringify(v ?? null) };
  return v as Record<string, unknown>;
}

/** Port of safeagents.scan.history() followed by recent(). Reasoning is never included. */
export function buildTrace(conv: Conversation, agentSteps: number, maxResultChars: number): AtifStep[] {
  const steps: AtifStep[] = [];
  const system = contentText(conv.system);
  if (system) steps.push({ source: "system", message: system });

  for (const m of conv.messages) {
    if (m.role === "system" || m.role === "developer") {
      steps.push({ source: "system", message: contentText(m.content) });
      continue;
    }
    if (m.toolResults.length) {
      // Results attach to the latest agent step, and only if it made calls.
      const agent = steps.findLast((s) => s.source === "agent");
      if (agent?.tool_calls?.length) {
        const results = (agent.observation ??= { results: [] }).results;
        for (const r of m.toolResults) {
          results.push({ source_call_id: String(r.id), content: contentText(r.content).slice(0, maxResultChars) });
        }
      }
    }
    if (m.role === "user") {
      const text = contentText(m.content);
      if (text) steps.push({ source: "user", message: text });
    } else if (m.role === "assistant") {
      const step: AtifStep = { source: "agent", message: contentText(m.content) };
      if (m.toolCalls.length) {
        step.tool_calls = m.toolCalls.map((c) => ({
          tool_call_id: String(c.id),
          function_name: String(c.name),
          arguments: atifArguments(c.args),
        }));
      }
      steps.push(step);
    }
  }

  // recent(): keep every user/system step and the last `agentSteps` agent steps.
  const agentIdx = steps.flatMap((s, i) => (s.source === "agent" ? [i] : []));
  const dropped = new Set(agentIdx.slice(0, Math.max(0, agentIdx.length - agentSteps)));
  return steps.filter((_, i) => !dropped.has(i));
}
