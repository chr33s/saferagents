import { describe, expect, it } from "vitest";
import { contentText, parseConversation } from "../src/conversation.ts";
import { atifArguments, buildTrace } from "../src/trace.ts";

const conv = (body: any) => parseConversation(body);

describe("contentText", () => {
  it("accepts strings and text/input_text parts only", () => {
    expect(contentText("hi")).toBe("hi");
    expect(
      contentText([
        { type: "text", text: "a" },
        { type: "input_text", text: "b" },
        { type: "image" },
        { type: "thinking", thinking: "x" },
        { type: "text", text: 3 },
      ]),
    ).toBe("a\nb");
    expect(contentText(null)).toBe("");
    expect(contentText({ text: "x" })).toBe("");
  });
});

describe("atifArguments", () => {
  it("follows upstream _tool_call normalization", () => {
    expect(atifArguments('{"a":1}')).toEqual({ a: 1 });
    expect(atifArguments({ a: 1 })).toEqual({ a: 1 });
    expect(atifArguments("not json")).toEqual({ input: "not json" });
    expect(atifArguments("[1,2]")).toEqual({ input: "[1,2]" });
    expect(atifArguments('"s"')).toEqual({ input: '"s"' });
    expect(atifArguments("null")).toEqual({ input: "null" });
    expect(atifArguments(undefined)).toEqual({ input: "null" });
    expect(atifArguments(5)).toEqual({ input: "5" });
  });
});

describe("buildTrace", () => {
  it("converts an Anthropic conversation, attaching tool results to the last agent step", () => {
    const body = {
      system: [{ type: "text", text: "sys" }],
      messages: [
        { role: "user", content: "do it" },
        {
          role: "assistant",
          content: [
            { type: "thinking", thinking: "hidden" },
            { type: "text", text: "ok" },
            { type: "tool_use", id: "t1", name: "Bash", input: { command: "ls" } },
          ],
        },
        {
          role: "user",
          content: [
            { type: "tool_result", tool_use_id: "t1", content: [{ type: "text", text: "a.txt" }] },
            { type: "text", text: "thanks" },
          ],
        },
      ],
    };
    expect(buildTrace(conv(body), 20, 2000)).toEqual([
      { source: "system", message: "sys" },
      { source: "user", message: "do it" },
      {
        source: "agent",
        message: "ok",
        tool_calls: [{ tool_call_id: "t1", function_name: "Bash", arguments: { command: "ls" } }],
        observation: { results: [{ source_call_id: "t1", content: "a.txt" }] },
      },
      { source: "user", message: "thanks" },
    ]);
  });

  it("converts an OpenAI conversation with role:tool results", () => {
    const body = {
      messages: [
        { role: "developer", content: "dev" },
        { role: "user", content: [{ type: "text", text: "go" }] },
        {
          role: "assistant",
          content: null,
          tool_calls: [{ id: "c1", type: "function", function: { name: "sh", arguments: '{"cmd":"ls"}' } }],
        },
        { role: "tool", tool_call_id: "c1", content: "out" },
      ],
    };
    expect(buildTrace(conv(body), 20, 2000)).toEqual([
      { source: "system", message: "dev" },
      { source: "user", message: "go" },
      {
        source: "agent",
        message: "",
        tool_calls: [{ tool_call_id: "c1", function_name: "sh", arguments: { cmd: "ls" } }],
        observation: { results: [{ source_call_id: "c1", content: "out" }] },
      },
    ]);
  });

  it("caps tool results at maxResultChars", () => {
    const body = {
      messages: [
        { role: "assistant", content: [{ type: "tool_use", id: "t", name: "Read", input: {} }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "t", content: "x".repeat(5000) }] },
      ],
    };
    expect(buildTrace(conv(body), 20, 2000)[0].observation!.results[0].content).toHaveLength(2000);
  });

  it("drops results when the last agent step has no tool calls", () => {
    const body = {
      messages: [
        { role: "assistant", content: "hi" },
        { role: "tool", tool_call_id: "x", content: "y" },
      ],
    };
    expect(buildTrace(conv(body), 20, 2000)).toEqual([{ source: "agent", message: "hi" }]);
  });

  it("recent(): keeps every user/system step and the last N agent steps", () => {
    const messages: any[] = [];
    for (let i = 0; i < 30; i++) {
      messages.push({ role: "user", content: `u${i}` });
      messages.push({ role: "assistant", content: `a${i}` });
    }
    const steps = buildTrace(conv({ system: "s", messages }), 20, 2000);
    expect(steps.filter((s) => s.source === "user")).toHaveLength(30);
    const agent = steps.filter((s) => s.source === "agent").map((s) => s.message);
    expect(agent).toHaveLength(20);
    expect(agent[0]).toBe("a10");
    expect(steps[0]).toEqual({ source: "system", message: "s" });
  });

  it("skips empty user text and garbage messages", () => {
    expect(
      buildTrace(
        conv({ messages: [null, 5, { role: "user", content: "" }, { role: "user", content: [{ type: "image" }] }] }),
        20,
        2000,
      ),
    ).toEqual([]);
    expect(buildTrace(conv({}), 20, 2000)).toEqual([]);
  });
});
