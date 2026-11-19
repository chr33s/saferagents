// The request, parsed once into a provider-neutral shape.

export type Block = Record<string, any>;

export interface ToolCall {
  id: unknown;
  name: unknown;
  /** Raw arguments: an object (Anthropic `input`) or a JSON string (OpenAI `arguments`). */
  args: unknown;
}

export interface ToolResult {
  id: unknown;
  content: unknown;
}

export interface Message {
  role: unknown;
  content: unknown;
  /** Object entries of `content` when it is a list. */
  blocks: Block[];
  /** Assistant calls: OpenAI `tool_calls`, then Anthropic `tool_use` blocks. */
  toolCalls: ToolCall[];
  /** Anthropic `tool_result` blocks in a user turn, or an OpenAI `role: "tool"` message. */
  toolResults: ToolResult[];
}

export interface Conversation {
  model: string;
  system: unknown;
  tools: unknown[];
  /** Server-executed tools the request enables (§4.4); rejected under SERVER_TOOLS=deny. */
  serverTools: string[];
  messages: Message[];
}

export const isObject = (v: unknown): v is Block => !!v && typeof v === "object";
export const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

function parseMessage(m: Block): Message {
  const blocks = list(m.content).filter(isObject);
  const toolCalls: ToolCall[] = [];
  const toolResults: ToolResult[] = [];
  if (m.role === "assistant") {
    for (const tc of list(m.tool_calls)) {
      if (isObject(tc) && isObject(tc.function)) {
        toolCalls.push({ id: tc.id, name: tc.function.name, args: tc.function.arguments });
      }
    }
    for (const b of blocks) if (b.type === "tool_use") toolCalls.push({ id: b.id, name: b.name, args: b.input });
  } else if (m.role === "user") {
    for (const b of blocks) if (b.type === "tool_result") toolResults.push({ id: b.tool_use_id, content: b.content });
  } else if (m.role === "tool") {
    toolResults.push({ id: m.tool_call_id, content: m.content });
  }
  return { role: m.role, content: m.content, blocks, toolCalls, toolResults };
}

/** Anthropic Messages / OpenAI Chat Completions; other APIs are mapped onto this shape first. */
export function parseConversation(body: Block, serverTools: string[] = []): Conversation {
  return {
    model: String(body.model ?? ""),
    system: body.system,
    tools: list(body.tools),
    serverTools,
    messages: list(body.messages).filter(isObject).map(parseMessage),
  };
}

/** Port of upstream utils.content_text: a string, or the `text` / `input_text` parts of a list. */
export function contentText(content: unknown): string {
  if (typeof content === "string") return content;
  return list(content)
    .filter(
      (b): b is Block => isObject(b) && (b.type === "text" || b.type === "input_text") && typeof b.text === "string",
    )
    .map((b) => b.text)
    .join("\n");
}
