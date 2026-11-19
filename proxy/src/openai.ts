import { parseConversation } from "./conversation.ts";
import { Tally, type Guard } from "./guard.ts";
import { guardStream, openaiData, openaiError, type FrameHandler, type SseFrame } from "./sse.ts";
import type { Provider } from "./types.ts";

interface Pending {
  choice: number;
  index: number;
  id?: string;
  name: string;
  args: string;
}

function streamHandler(guard: Guard): FrameHandler {
  const pending = new Map<string, Pending>();
  const tallies = new Map<number, Tally>();
  let template: any = {};

  const tally = (choice: number) => {
    if (!tallies.has(choice)) tallies.set(choice, new Tally());
    return tallies.get(choice)!;
  };

  function absorb(choice: number, tc: any) {
    const index = tc?.index ?? 0;
    const key = `${choice}:${index}`;
    const c: Pending = pending.get(key) ?? { choice, index, name: "", args: "" };
    if (typeof tc?.id === "string") c.id = tc.id;
    if (typeof tc?.function?.name === "string") c.name += tc.function.name;
    if (typeof tc?.function?.arguments === "string") c.args += tc.function.arguments;
    pending.set(key, c);
  }

  /** One chunk with the choice's allowed calls (indices renumbered from 0) and notices as content. */
  async function release(choice: number): Promise<string> {
    const calls = [...pending.entries()].filter(([, c]) => c.choice === choice).sort((a, b) => a[1].index - b[1].index);
    if (!calls.length) return "";
    const kept: Pending[] = [];
    const notices: string[] = [];
    for (const [key, c] of calls) {
      pending.delete(key);
      const d = tally(choice).add(await guard.review(c.name, c.args));
      if (d.keep) kept.push(c);
      else notices.push(d.notice);
    }
    const delta: any = {};
    if (kept.length) {
      delta.tool_calls = kept.map((c, i) => ({
        index: i,
        id: c.id,
        type: "function",
        function: { name: c.name, arguments: c.args },
      }));
    }
    if (notices.length) delta.content = notices.join("\n");
    const { usage: _usage, ...rest } = template;
    return openaiData({ ...rest, choices: [{ index: choice, delta, finish_reason: null }] });
  }

  async function releaseAll(): Promise<string> {
    let out = "";
    for (const choice of new Set([...pending.values()].map((c) => c.choice))) out += await release(choice);
    return out;
  }

  return {
    async onFrame(f: SseFrame) {
      if (f.data === null) return f.raw;
      let ev: any;
      try {
        ev = JSON.parse(f.data);
      } catch {
        return (await releaseAll()) + f.raw; // e.g. [DONE]
      }
      if (!ev || !Array.isArray(ev.choices)) return f.raw;

      let changed = false;
      const finished: number[] = [];
      for (const ch of ev.choices) {
        if (!ch || typeof ch !== "object") continue;
        const ci = ch.index ?? 0;
        if (ch.delta && typeof ch.delta === "object" && "tool_calls" in ch.delta) {
          changed = true;
          for (const tc of ch.delta.tool_calls ?? []) absorb(ci, tc);
          delete ch.delta.tool_calls;
        }
        if (typeof ch.finish_reason === "string") finished.push(ci);
      }
      template = ev;
      if (!finished.length) return changed ? openaiData(ev) : f.raw;

      let out = "";
      for (const ci of finished) out += await release(ci);
      for (const ch of ev.choices) {
        if (ch?.finish_reason === "tool_calls" && tallies.get(ch.index ?? 0)?.endTurn) ch.finish_reason = "stop";
      }
      return out + openaiData(ev);
    },
    onEnd: releaseAll,
    onError() {
      pending.clear();
      return openaiError("internal error");
    },
  };
}

async function guardJson(res: any, guard: Guard): Promise<boolean> {
  let changed = false;
  for (const choice of Array.isArray(res?.choices) ? res.choices : []) {
    const message = choice?.message;
    if (!message || !Array.isArray(message.tool_calls)) continue;
    const tally = new Tally();
    const kept = [];
    const notices: string[] = [];
    for (const tc of message.tool_calls) {
      const d = tally.add(await guard.review(String(tc?.function?.name ?? ""), String(tc?.function?.arguments ?? "")));
      if (d.keep) kept.push(tc);
      else notices.push(d.notice);
    }
    if (!notices.length) continue;
    changed = true;
    if (tally.endTurn) {
      delete message.tool_calls;
      if (choice.finish_reason === "tool_calls") choice.finish_reason = "stop";
    } else {
      message.tool_calls = kept;
    }
    message.content = [typeof message.content === "string" && message.content ? message.content : null, ...notices]
      .filter(Boolean)
      .join("\n");
  }
  return changed;
}

/** Chat Completions (OpenAI, xAI). */
export const openai: Provider = {
  parse: (body) => parseConversation(body),
  stream: (guard) => guardStream(streamHandler(guard)),
  guardJson,
};
