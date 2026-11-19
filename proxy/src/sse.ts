export interface SseFrame {
  raw: string;
  data: string | null;
}

export class SseParser {
  private buf = "";

  push(chunk: string): SseFrame[] {
    this.buf += chunk;
    const out: SseFrame[] = [];
    let m: RegExpExecArray | null;
    while ((m = /\r\n\r\n|\n\n/.exec(this.buf))) {
      const end = m.index + m[0].length;
      out.push(parseFrame(this.buf.slice(0, m.index), this.buf.slice(0, end)));
      this.buf = this.buf.slice(end);
    }
    return out;
  }

  end(): SseFrame[] {
    if (!this.buf) return [];
    const b = this.buf;
    this.buf = "";
    return [parseFrame(b, `${b}\n\n`)];
  }
}

function parseFrame(body: string, raw: string): SseFrame {
  const data: string[] = [];
  for (const line of body.split(/\r\n|\n|\r/)) {
    const i = line.indexOf(":");
    const name = i === -1 ? line : line.slice(0, i);
    let v = i === -1 ? "" : line.slice(i + 1);
    if (v.startsWith(" ")) v = v.slice(1);
    if (name === "data") data.push(v);
  }
  return { raw, data: data.length ? data.join("\n") : null };
}

/** Data payloads of a complete SSE text, JSON-decoded where possible. */
export function sseData(text: string): unknown[] {
  const p = new SseParser();
  return [...p.push(text), ...p.end()].flatMap((f) => {
    if (f.data === null) return [];
    try {
      return [JSON.parse(f.data)];
    } catch {
      return [f.data];
    }
  });
}

/** `event: <type>` framing, used by Anthropic Messages and the OpenAI Responses API. */
export const namedEvent = (ev: { type: string }) => `event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`;
export const openaiData = (ev: unknown) => `data: ${JSON.stringify(ev)}\n\n`;
export const anthropicError = (message: string) =>
  namedEvent({ type: "error", error: { type: "api_error", message: `saferagents: ${message}` } } as any);
export const openaiError = (message: string) =>
  openaiData({ error: { type: "server_error", message: `saferagents: ${message}` } });

export interface FrameHandler {
  /** Output for one frame ("" to hold it). */
  onFrame(f: SseFrame): Promise<string>;
  /** Output after the last frame. */
  onEnd(): Promise<string>;
  /** Drops held calls and returns the provider's error frame. */
  onError(): string;
}

/**
 * Bytes in, bytes out, in one stream stage. An exception drops held calls and ends the stream
 * with the provider's error frame, so an incomplete call is never released.
 */
export function guardStream(h: FrameHandler): TransformStream<Uint8Array, Uint8Array> {
  const parser = new SseParser();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  const fail = (ctl: TransformStreamDefaultController<Uint8Array>, e: unknown) => {
    console.error("saferagents stream error", String(e));
    ctl.enqueue(encoder.encode(h.onError()));
  };
  const emit = async (ctl: TransformStreamDefaultController<Uint8Array>, frames: SseFrame[]) => {
    for (const f of frames) {
      const out = await h.onFrame(f);
      if (out) ctl.enqueue(encoder.encode(out));
    }
  };
  return new TransformStream<Uint8Array, Uint8Array>({
    async transform(chunk, ctl) {
      try {
        await emit(ctl, parser.push(decoder.decode(chunk, { stream: true })));
      } catch (e) {
        fail(ctl, e);
        ctl.terminate();
      }
    },
    async flush(ctl) {
      try {
        await emit(ctl, [...parser.push(decoder.decode()), ...parser.end()]);
        const out = await h.onEnd();
        if (out) ctl.enqueue(encoder.encode(out));
      } catch (e) {
        fail(ctl, e);
      }
    },
  });
}
