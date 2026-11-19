import type { FindingSeverity } from "./constants.ts";
import type { Conversation } from "./conversation.ts";
import type { Guard } from "./guard.ts";

export interface Finding {
  ruleId: string;
  severity: FindingSeverity;
  title: string;
}

export interface AtifStep {
  source: "system" | "user" | "agent";
  message: string;
  tool_calls?: Array<{ tool_call_id: string; function_name: string; arguments: Record<string, unknown> }>;
  observation?: { results: Array<{ source_call_id: string; content: string }> };
}

/** Everything that differs between model APIs. */
export interface Provider {
  /** The request in the shared conversation shape, including the server-executed tools it enables. */
  parse(body: Record<string, any>): Conversation;
  stream(guard: Guard): TransformStream<Uint8Array, Uint8Array>;
  /** Guards a non-streaming body in place; true if anything changed. */
  guardJson(body: any, guard: Guard): Promise<boolean>;
}

export interface Env {
  ATIF_SCANNER: { scan(request: string): Promise<string> };
  AI?: any;
  TRACE_BUCKET?: R2Bucket;
  PROXY_AUTH_TOKEN?: string;
  [key: string]: unknown;
}
