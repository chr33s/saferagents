import { describe, expect, it, vi } from "vitest";
import { anthropicError, anthropicEvent, guardStream, openaiData, openaiError, SseParser } from "../src/sse.ts";

function parseAll(chunks: string[]) {
  const p = new SseParser();
  const frames = chunks.flatMap((c) => p.push(c));
  return [...frames, ...p.end()];
}

const STREAM =
  'event: message_start\ndata: {"type":"message_start"}\n\n' +
  ": keep-alive comment\n\n" +
  'event: content_block_delta\r\ndata: {"type":"content_block_delta",\r\ndata: "index":0}\r\n\r\n' +
  'data:{"nospace":true}\n\n' +
  "data: [DONE]\n\n";

describe("SseParser", () => {
  it("parses LF and CRLF frames, multi-line data, comments and [DONE]", () => {
    const frames = parseAll([STREAM]);
    expect(frames.map((f) => f.data)).toEqual([
      '{"type":"message_start"}',
      null,
      '{"type":"content_block_delta",\n"index":0}',
      '{"nospace":true}',
      "[DONE]",
    ]);
    expect(JSON.parse(frames[2].data!)).toEqual({ type: "content_block_delta", index: 0 });
    expect(frames.map((f) => f.raw).join("")).toBe(STREAM);
  });

  it("gives identical frames for every split offset (two pieces)", () => {
    const whole = parseAll([STREAM]);
    for (let i = 0; i <= STREAM.length; i++) {
      const split = parseAll([STREAM.slice(0, i), STREAM.slice(i)]);
      expect(split, `offset ${i}`).toEqual(whole);
    }
  });

  it("gives identical frames when fed one byte at a time", () => {
    expect(parseAll([...STREAM])).toEqual(parseAll([STREAM]));
  });

  it("removes only one leading space per data line", () => {
    expect(parseAll(["data:  two\n\n"])[0].data).toBe(" two");
  });

  it("returns a trailing frame with no terminator on end(), terminated", () => {
    const frames = parseAll(['data: {"a":1}\n\ndata: {"b":2}']);
    expect(frames).toHaveLength(2);
    expect(frames[1]).toEqual({ raw: 'data: {"b":2}\n\n', data: '{"b":2}' });
  });

  it("returns nothing on end() with an empty buffer", () => {
    const p = new SseParser();
    p.push("data: x\n\n");
    expect(p.end()).toEqual([]);
  });

  it("handles a CRLF terminator split across chunks", () => {
    const frames = parseAll(["data: 1\r\n\r", "\ndata: 2\r\n\r\n"]);
    expect(frames.map((f) => f.data)).toEqual(["1", "2"]);
  });
});

describe("encoders", () => {
  it("encodes Anthropic events and OpenAI data", () => {
    expect(anthropicEvent({ type: "ping" })).toBe('event: ping\ndata: {"type":"ping"}\n\n');
    expect(openaiData({ a: 1 })).toBe('data: {"a":1}\n\n');
    expect(JSON.parse(anthropicError("boom").split("data: ")[1])).toEqual({
      type: "error",
      error: { type: "api_error", message: "saferagents: boom" },
    });
    expect(JSON.parse(openaiError("boom").slice(6))).toEqual({
      error: { type: "server_error", message: "saferagents: boom" },
    });
  });
});

describe("guardStream", () => {
  const bytes = (text: string) =>
    new ReadableStream<Uint8Array>({
      start(c) {
        for (const b of new TextEncoder().encode(text)) c.enqueue(new Uint8Array([b]));
        c.close();
      },
    });

  it("decodes multi-byte characters split across chunks and encodes the handler output", async () => {
    const seen: string[] = [];
    const t = guardStream({
      onFrame: async (f) => {
        seen.push(f.data ?? "");
        return f.raw.toUpperCase();
      },
      onEnd: async () => "END",
      onError: () => "ERR",
    });
    expect(await new Response(bytes("data: héllo 🦀\n\n").pipeThrough(t)).text()).toBe("DATA: HÉLLO 🦀\n\nEND");
    expect(seen).toEqual(["héllo 🦀"]);
  });

  it("ends with the handler's error frame when a frame throws", async () => {
    const t = guardStream({
      onFrame: async () => {
        throw new Error("bug");
      },
      onEnd: async () => "END",
      onError: () => "ERR",
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await new Response(bytes("data: x\n\ndata: y\n\n").pipeThrough(t)).text()).toBe("ERR");
  });
});
