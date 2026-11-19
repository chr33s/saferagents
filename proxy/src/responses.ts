// OpenAI Responses API (OpenAI, xAI): output items stream as `response.output_item.added` … `.done`.
import { isObject, list, parseConversation, type Block } from "./conversation.ts";
import type { Guard } from "./guard.ts";
import { guardStream, namedEvent, type FrameHandler, type SseFrame } from "./sse.ts";
import type { Provider } from "./types.ts";

/** Client-executed call items, as the (name, raw arguments) the guard reviews. */
const CALL_ITEMS: Record<string, (item: Block) => [unknown, unknown]> = {
  function_call: (i) => [i.name, i.arguments],
  custom_tool_call: (i) => [i.name, i.input],
  // Command arrays are joined so a command line reads as one, like a Bash tool's `command`.
  local_shell_call: (i) => ["local_shell", JSON.stringify({ ...i.action, command: list(i.action?.command).join(" ") })],
  shell_call: (i) => ["shell", JSON.stringify({ ...i.action, commands: list(i.action?.commands).join("\n") })],
  apply_patch_call: (i) => ["apply_patch", JSON.stringify(i.operation ?? {})],
  computer_call: (i) => ["computer_use_preview", JSON.stringify(i.action ?? {})],
};
// Calls run by the provider before the response arrives (§4.4): forwarded and never held.
const SERVER_CALL_ITEMS = new Set([
  "web_search_call",
  "file_search_call",
  "code_interpreter_call",
  "image_generation_call",
  "mcp_call",
  "mcp_list_tools",
  "mcp_approval_request",
  "x_search_call",
  "code_execution_call",
  "collections_search_call",
]);
const CLIENT_TOOL_TYPES = new Set([
  "function",
  "custom",
  "local_shell",
  "shell",
  "apply_patch",
  "computer_use_preview",
]);

/** A call item the client would execute. Unknown `*_call` types are held too, and fail as undeclared tools. */
const isClientCall = (item: unknown): boolean =>
  isObject(item) &&
  typeof item.type === "string" &&
  (item.type in CALL_ITEMS || (item.type.endsWith("_call") && !SERVER_CALL_ITEMS.has(item.type)));

export function callOf(item: Block): { name: string; args: string } {
  const [name, args] = CALL_ITEMS[item.type]?.(item) ?? [item.type, JSON.stringify(item)];
  return { name: String(name ?? ""), args: typeof args === "string" ? args : JSON.stringify(args ?? {}) };
}

const textPart = (p: unknown) =>
  isObject(p) && p.type === "output_text"
    ? { ...p, type: "text" }
    : isObject(p) && p.type === "input_image"
      ? { type: "image" }
      : p;

/** Responses `input` items as a Chat Completions conversation. */
function parse(body: Block) {
  const messages: Block[] = [];
  const items = typeof body.input === "string" ? [{ role: "user", content: body.input }] : list(body.input);
  for (const item of items.filter(isObject)) {
    if (isClientCall(item)) {
      const { name, args } = callOf(item);
      let turn = messages.at(-1);
      if (turn?.role !== "assistant") messages.push((turn = { role: "assistant", content: "" }));
      (turn.tool_calls ??= []).push({ id: item.call_id, function: { name, arguments: args } });
    } else if (typeof item.type === "string" && item.type.endsWith("_call_output")) {
      const output = typeof item.output === "string" ? item.output : list(item.output).map(textPart);
      messages.push({ role: "tool", tool_call_id: item.call_id, content: output });
    } else if (item.type === "message" || (item.type === undefined && "role" in item)) {
      messages.push({
        role: item.role,
        content: Array.isArray(item.content) ? item.content.map(textPart) : item.content,
      });
    }
  }
  const tools = list(body.tools).map((t) => (isObject(t) && t.name === undefined ? { ...t, name: t.type } : t));
  const serverTools = tools
    .filter((t): t is Block => isObject(t) && !CLIENT_TOOL_TYPES.has(t.type))
    .map((t) => String(t.type));
  return parseConversation({ model: body.model, system: body.instructions, tools, messages }, serverTools);
}

const noticeItem = (id: string, text: string) => ({
  type: "message",
  id,
  status: "completed",
  role: "assistant",
  content: [{ type: "output_text", text, annotations: [] }],
});

/** The events a client needs to build a text message item in place of a blocked call. */
function noticeEvents(outputIndex: number, item: ReturnType<typeof noticeItem>): string {
  const part = item.content[0];
  const at = { output_index: outputIndex, item_id: item.id, content_index: 0 };
  return [
    {
      type: "response.output_item.added",
      output_index: outputIndex,
      item: { ...item, status: "in_progress", content: [] },
    },
    { type: "response.content_part.added", ...at, part: { ...part, text: "" } },
    { type: "response.output_text.delta", ...at, delta: part.text },
    { type: "response.output_text.done", ...at, text: part.text },
    { type: "response.content_part.done", ...at, part },
    { type: "response.output_item.done", output_index: outputIndex, item },
  ]
    .map(namedEvent)
    .join("");
}

const errorEvent = (message: string) =>
  namedEvent({ type: "error", code: "server_error", message: `saferagents: ${message}`, param: null } as any);

const TERMINAL = new Set(["response.completed", "response.incomplete", "response.failed"]);

function streamHandler(guard: Guard): FrameHandler {
  const held = new Map<number, string[]>();
  const replaced = new Map<number, ReturnType<typeof noticeItem>>();
  let terminated = false;

  async function release(index: number, item: Block, frames: string[]): Promise<string> {
    const { name, args } = callOf(item);
    const d = await guard.review(name, args);
    if (d.keep) return frames.join("");
    const notice = noticeItem(`msg_saferagents_${item.id ?? index}`, d.notice);
    replaced.set(index, notice);
    return noticeEvents(index, notice);
  }

  return {
    async onFrame(f: SseFrame) {
      if (f.data === null) return f.raw;
      let ev: any;
      try {
        ev = JSON.parse(f.data);
      } catch {
        return f.raw;
      }
      if (!isObject(ev) || typeof ev.type !== "string") return f.raw;
      const index = ev.output_index;

      if (ev.type === "response.output_item.added" && isClientCall(ev.item)) {
        held.set(index, [f.raw]);
        return "";
      }
      if (typeof index === "number" && held.has(index)) {
        const frames = held.get(index)!;
        frames.push(f.raw);
        if (ev.type !== "response.output_item.done") return "";
        held.delete(index);
        return release(index, ev.item, frames);
      }
      if (TERMINAL.has(ev.type)) {
        terminated = true;
        const output = ev.response?.output;
        if (Array.isArray(output) && replaced.size) {
          for (const [i, item] of replaced) if (i < output.length) output[i] = item;
          return namedEvent(ev as { type: string });
        }
      } else if (ev.type === "error") {
        held.clear();
        terminated = true;
      }
      return f.raw;
    },
    async onEnd() {
      held.clear();
      return terminated ? "" : errorEvent("upstream stream ended before response.completed");
    },
    onError() {
      held.clear();
      return errorEvent("internal error");
    },
  };
}

async function guardJson(res: any, guard: Guard): Promise<boolean> {
  if (!Array.isArray(res?.output)) return false;
  let changed = false;
  for (const [i, item] of res.output.entries()) {
    if (!isClientCall(item)) continue;
    const { name, args } = callOf(item);
    const d = await guard.review(name, args);
    if (!d.keep) {
      res.output[i] = noticeItem(`msg_saferagents_${item.id ?? i}`, d.notice);
      changed = true;
    }
  }
  return changed;
}

export const responses: Provider = {
  parse,
  stream: (guard) => guardStream(streamHandler(guard)),
  guardJson,
};
