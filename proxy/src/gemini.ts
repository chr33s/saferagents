// Gemini API (generateContent / streamGenerateContent). Each functionCall part arrives complete in one
// chunk, so calls are reviewed in place with nothing held.
import { isObject, list, parseConversation, type Block } from "./conversation.ts";
import type { Guard } from "./guard.ts";
import { guardStream, type FrameHandler, type SseFrame } from "./sse.ts";
import type { Provider } from "./types.ts";

/** Gemini parts as Anthropic-style blocks; thought parts become `thinking` so they are never trusted or traced. */
function blocks(parts: unknown): Block[] {
  return list(parts)
    .filter(isObject)
    .map((p) => {
      if (p.thought) return { type: "thinking", thinking: String(p.text ?? "") };
      if (typeof p.text === "string") return { type: "text", text: p.text };
      if (isObject(p.functionCall)) {
        const fc = p.functionCall;
        return { type: "tool_use", id: fc.id ?? fc.name, name: fc.name, input: fc.args ?? {} };
      }
      if (isObject(p.functionResponse)) {
        const fr = p.functionResponse;
        return { type: "tool_result", tool_use_id: fr.id ?? fr.name, content: JSON.stringify(fr.response ?? {}) };
      }
      if (p.inlineData || p.fileData) return { type: "document" };
      return { type: "provider_part" }; // executableCode, codeExecutionResult, …
    });
}

function parse(body: Block) {
  const tools: Block[] = [];
  const serverTools: string[] = [];
  for (const t of list(body.tools).filter(isObject)) {
    for (const [key, value] of Object.entries(t)) {
      if (key !== "functionDeclarations") serverTools.push(key); // googleSearch, codeExecution, urlContext, …
      else for (const d of list(value).filter(isObject)) tools.push({ ...d, input_schema: d.parameters ?? {} });
    }
  }
  const system = body.systemInstruction;
  return parseConversation(
    {
      model: body.model,
      system: typeof system === "string" ? system : blocks(isObject(system) ? system.parts : undefined),
      tools,
      messages: list(body.contents)
        .filter(isObject)
        .map((c) => ({ role: c.role === "model" ? "assistant" : "user", content: blocks(c.parts) })),
    },
    serverTools,
  );
}

/** Reviews every functionCall part of a response in place; true if any was replaced. */
async function guardResponse(res: unknown, guard: Guard): Promise<boolean> {
  let changed = false;
  for (const candidate of list(isObject(res) ? res.candidates : undefined).filter(isObject)) {
    const parts = list(candidate.content?.parts);
    for (const [i, part] of parts.entries()) {
      if (!isObject(part) || !isObject(part.functionCall)) continue;
      const fc = part.functionCall;
      const name = String(fc.name ?? "");
      // Partial-argument streaming (Vertex) can't be reviewed before the call completes: fail closed.
      const d =
        fc.partialArgs || fc.willContinue
          ? {
              keep: false as const,
              notice: `[saferagents] blocked call to \`${name}\`: partial function-call arguments are not supported`,
            }
          : await guard.review(name, JSON.stringify(fc.args ?? {}));
      if (!d.keep) {
        parts[i] = { text: d.notice };
        changed = true;
      }
    }
  }
  return changed;
}

const errorData = (message: string) =>
  `data: ${JSON.stringify({ error: { code: 500, message: `saferagents: ${message}`, status: "INTERNAL" } })}\n\n`;

function streamHandler(guard: Guard): FrameHandler {
  return {
    async onFrame(f: SseFrame) {
      if (f.data === null) return f.raw;
      let ev: unknown;
      try {
        ev = JSON.parse(f.data);
      } catch {
        return f.raw;
      }
      return (await guardResponse(ev, guard)) ? `data: ${JSON.stringify(ev)}\n\n` : f.raw;
    },
    onEnd: async () => "",
    onError: () => errorData("internal error"),
  };
}

export const gemini: Provider = {
  parse,
  stream: (guard) => guardStream(streamHandler(guard)),
  // Non-SSE streamGenerateContent returns a JSON array of responses.
  async guardJson(body, guard) {
    let changed = false;
    for (const res of Array.isArray(body) ? body : [body]) changed = (await guardResponse(res, guard)) || changed;
    return changed;
  },
};
