import { list, parseConversation } from "./conversation.ts";
import { Tally, type Guard } from "./guard.ts";
import { anthropicError, namedEvent, guardStream, type FrameHandler, type SseFrame } from "./sse.ts";
import type { Provider } from "./types.ts";

interface Held {
  index: number;
  name: string;
  input: string;
  raw: string[];
}

// Anthropic-defined tools executed by the client (§4.4). Any other typed tool without input_schema runs server-side.
const CLIENT_TOOL_TYPE =
  /^(?:custom|bash_\d{8}|text_editor_\d{8}|memory_\d{8}|computer_\d{8}|(?:computer|browser)_toolset_\d{8})$/;

export function serverTools(body: Record<string, any>): string[] {
  const found = list(body.mcp_servers).length ? ["mcp_servers"] : [];
  for (const t of list(body.tools) as any[]) {
    if (typeof t?.type === "string" && !t.input_schema && !CLIENT_TOOL_TYPE.test(t.type)) found.push(t.type);
  }
  return found;
}

/** Toolset members (computer/browser) are reviewed as "<toolset_name>:<name>" (§4.4). */
export function reviewName(block: any): string {
  const name = String(block?.name ?? "");
  return typeof block?.toolset_name === "string" ? `${block.toolset_name}:${name}` : name;
}

/** A blocked call becomes a text block at the same index (Claude Code builds text only from deltas). */
const noticeBlock = (index: number, notice: string) =>
  namedEvent({ type: "content_block_start", index, content_block: { type: "text", text: "" } } as any) +
  namedEvent({ type: "content_block_delta", index, delta: { type: "text_delta", text: notice } } as any) +
  namedEvent({ type: "content_block_stop", index } as any);

function streamHandler(guard: Guard): FrameHandler {
  const tally = new Tally();
  let held: Held | null = null;
  let terminated = false; // saw message_stop or error

  async function release(h: Held): Promise<string> {
    const d = tally.add(await guard.review(h.name, h.input));
    return d.keep ? h.raw.join("") : noticeBlock(h.index, d.notice);
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
      if (!ev || typeof ev !== "object") return f.raw;
      const holding = held !== null && ev.index === held.index;

      switch (ev.type) {
        case "content_block_start":
          if (ev.content_block?.type === "tool_use") {
            const start = ev.content_block.input;
            held = {
              index: ev.index,
              name: reviewName(ev.content_block),
              input: start && typeof start === "object" && Object.keys(start).length ? JSON.stringify(start) : "",
              raw: [f.raw],
            };
            return "";
          }
          break;
        case "content_block_delta":
          if (holding) {
            const pj = ev.delta?.partial_json;
            if (typeof pj === "string") held!.input += pj;
            held!.raw.push(f.raw);
            return "";
          }
          break;
        case "content_block_stop":
          if (holding) {
            const h = held!;
            held = null;
            h.raw.push(f.raw);
            return release(h);
          }
          break;
        case "message_delta":
          if (tally.endTurn && ev.delta?.stop_reason === "tool_use") {
            ev.delta.stop_reason = "end_turn";
            return namedEvent(ev);
          }
          break;
        case "message_stop":
          terminated = true;
          break;
        case "error":
          held = null; // an incomplete call is never released
          terminated = true;
          break;
      }
      return f.raw;
    },
    async onEnd() {
      held = null;
      return terminated ? "" : anthropicError("upstream stream ended before message_stop");
    },
    onError() {
      held = null;
      return anthropicError("internal error");
    },
  };
}

async function guardJson(res: any, guard: Guard): Promise<boolean> {
  if (!Array.isArray(res?.content)) return false;
  const tally = new Tally();
  let changed = false;
  for (const [i, block] of res.content.entries()) {
    if (block?.type !== "tool_use") continue;
    const d = tally.add(await guard.review(reviewName(block), JSON.stringify(block.input ?? {})));
    if (!d.keep) {
      res.content[i] = { type: "text", text: d.notice };
      changed = true;
    }
  }
  if (tally.endTurn && res.stop_reason === "tool_use") res.stop_reason = "end_turn";
  return changed;
}

export const anthropic: Provider = {
  parse: (body) => parseConversation(body, serverTools(body)),
  stream: (guard) => guardStream(streamHandler(guard)),
  guardJson,
};
