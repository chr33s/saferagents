import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.ts";
import { runJudge } from "../src/judge.ts";
import cases from "./fixtures/judge-cases.json";
import { fakeAI, OFFICIAL } from "./helpers.ts";

// §9.5 regression set: structure, and that every case reaches each judge as data only.
// Live accuracy runs against Workers AI with `node scripts/judge-eval.ts`.
describe("judge regression set (§9.5)", () => {
  it("has the labelled block and allow cases", () => {
    expect(cases.length).toBeGreaterThanOrEqual(100);
    expect(cases.filter((c) => c.expect === "block").length).toBeGreaterThanOrEqual(40);
    expect(cases.filter((c) => c.expect === "allow").length).toBeGreaterThanOrEqual(40);
    expect(new Set(cases.map((c) => c.id)).size).toBe(cases.length);
  });

  const llama = loadConfig({ ...OFFICIAL, AI: {}, JUDGE_MODEL: "@cf/meta/llama-3.3-70b-instruct-fp8-fast" });
  const clef = loadConfig({ ...OFFICIAL, AI: {} });

  it.each(cases.map((c) => [c.id, c] as const))("%s reaches the Llama judge with no tag escape", async (_id, c) => {
    const ai = fakeAI(() => ({ response: { verdict: "block", reason: "x" } }));
    await runJudge(ai, llama, c.task, c.tool, JSON.stringify(c.args), c.findings as any);
    const user: string = ai.calls[0].input.messages[1].content;
    for (const tag of [
      "<task>",
      "</task>",
      "<tool_call ",
      "</tool_call>",
      "<scanner_findings>",
      "</scanner_findings>",
    ]) {
      expect(user.split(tag).length - 1, tag).toBe(1);
    }
  });

  it.each(cases.map((c) => [c.id, c] as const))("%s reaches clef-flash as typed state", async (_id, c) => {
    const ai = fakeAI(() => ({ answers: { block: { noul: 0.5 } } }));
    await runJudge(ai, clef, c.task, c.tool, JSON.stringify(c.args), c.findings as any);
    const state = ai.calls[0].input.state;
    expect(state.user_task).toBe(c.task);
    expect(state.tool_call).toEqual({ name: c.tool, arguments: c.args });
    expect(state.scanner_findings).toEqual(c.findings);
  });
});
