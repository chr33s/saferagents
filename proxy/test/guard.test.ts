import { describe, expect, it } from "vitest";
import { Tally, type Decision, type Guard } from "../src/guard.ts";
import { anthropicBody, fakeAI, fakeScanner, makeGuard } from "./helpers.ts";

let last: Decision;
async function allow(guard: Guard, name: string, args: string): Promise<boolean> {
  last = await guard.review(name, args);
  return last.keep;
}
const notice = () => (last.keep ? "" : last.notice);

const ls = JSON.stringify({ command: "ls" });
const conftest = JSON.stringify({ file_path: "tests/conftest.py", content: "x" });
const medium = fakeScanner({ conftest: [{ ruleId: "tamper.harness_hooks", severity: "medium" }] }).scan;
const never = () => new Promise<string>(() => {});
const clef = (p: unknown) => fakeAI(() => ({ answers: { block: { noul: p } } }));

describe("Guard: scanner verdicts", () => {
  it("passes with no findings, and does not audit", async () => {
    const { guard, audits } = makeGuard(anthropicBody());
    expect(await allow(guard, "Bash", ls)).toBe(true);
    expect(audits).toEqual([]);
  });

  it("blocks findings at or above BLOCK_SEVERITY without the judge", async () => {
    const ai = clef(0);
    const scanner = fakeScanner({ ls: [{ ruleId: "saferagents.env_exfil", severity: "high" }] }).scan;
    const { guard, audits } = makeGuard(anthropicBody(), { scanner, ai, env: { ENABLE_JUDGE: "true" } });
    expect(await allow(guard, "Bash", ls)).toBe(false);
    expect(notice()).toBe("[saferagents] blocked call to `Bash`: atif-scan: saferagents.env_exfil (high)");
    expect(ai.calls).toEqual([]);
    expect(audits[0]).toMatchObject({ verdict: "blocked", tool: "Bash" });
  });

  it("BLOCK_SEVERITY=critical turns high findings into suspicious", async () => {
    const scanner = fakeScanner({ ls: [{ ruleId: "x", severity: "high" }] }).scan;
    const { guard, audits } = makeGuard(anthropicBody(), {
      scanner,
      env: { BLOCK_SEVERITY: "critical", SUSPICIOUS_ACTION: "allow" },
    });
    expect(await allow(guard, "Bash", ls)).toBe(true);
    expect(audits[0].verdict).toBe("suspicious");
  });

  it("treats unknown severities from the scanner as critical", async () => {
    const scanner = async () => JSON.stringify({ findings: [{ ruleId: "x", severity: "weird", title: "t" }] });
    const { guard } = makeGuard(anthropicBody(), { scanner, env: { BLOCK_SEVERITY: "critical" } });
    expect(await allow(guard, "Bash", ls)).toBe(false);
    expect(notice()).toContain("x (critical)");
  });

  it("Stage 1 block skips the scanner", async () => {
    const s = fakeScanner();
    const { guard } = makeGuard(anthropicBody(), { scanner: s.scan });
    expect(await allow(guard, "Nope", ls)).toBe(false);
    expect(s.payloads).toEqual([]);
    expect(notice()).toBe("[saferagents] blocked call to `Nope`: STAGE1-UNDECLARED-TOOL: undeclared tool");
  });
});

describe("Guard: SUSPICIOUS_ACTION (judge disabled)", () => {
  it("defaults to block", async () => {
    const { guard } = makeGuard(anthropicBody(), { scanner: medium });
    expect(await allow(guard, "Write", conftest)).toBe(false);
    expect(notice()).toContain("tamper.harness_hooks (medium); no judge configured");
  });
  it("allow passes and audits as suspicious", async () => {
    const { guard, audits } = makeGuard(anthropicBody(), { scanner: medium, env: { SUSPICIOUS_ACTION: "allow" } });
    expect(await allow(guard, "Write", conftest)).toBe(true);
    expect(audits[0].verdict).toBe("suspicious");
  });
  it("Stage 1 unresolved target is suspicious → blocked by default", async () => {
    const { guard } = makeGuard(anthropicBody(), {});
    expect(await allow(guard, "Bash", JSON.stringify({ command: "curl $URL" }))).toBe(false);
    expect(notice()).toContain("STAGE1-UNRESOLVED-TARGET (medium)");
  });
  it("ENABLE_JUDGE=true without an AI binding counts as disabled", async () => {
    const { guard, cfg } = makeGuard(anthropicBody(), { scanner: medium, env: { ENABLE_JUDGE: "true" } });
    expect(cfg.judgeEnabled).toBe(false);
    expect(await allow(guard, "Write", conftest)).toBe(false);
  });
});

describe("Guard: SCANNER_FAIL_MODE", () => {
  const failures: Array<[string, () => Promise<string>]> = [
    [
      "throw",
      async () => {
        throw new Error("rpc failed");
      },
    ],
    ["malformed", async () => JSON.stringify({ nope: true })],
    ["non-JSON", async () => "not json"],
  ];
  for (const [label, scanner] of failures) {
    it(`${label} → blocked under block`, async () => {
      const { guard, audits } = makeGuard(anthropicBody(), { scanner });
      expect(await allow(guard, "Bash", ls)).toBe(false);
      expect(notice()).toContain("SCANNER-ERROR: scanner unavailable");
      expect(audits[0].note).toBeTruthy();
    });
    it(`${label} → passed and audited under allow`, async () => {
      const { guard, audits } = makeGuard(anthropicBody(), { scanner, env: { SCANNER_FAIL_MODE: "allow" } });
      expect(await allow(guard, "Bash", ls)).toBe(true);
      expect(audits[0]).toMatchObject({ verdict: "passed" });
      expect(audits[0].note).toMatch(/^scanner_error: /);
    });
  }
  it("timeout → blocked under block", async () => {
    const { guard } = makeGuard(anthropicBody(), { scanner: never, env: { SCANNER_TIMEOUT_MS: "20" } });
    expect(await allow(guard, "Bash", ls)).toBe(false);
    expect(notice()).toContain("SCANNER-ERROR");
  });
  it("timeout → passed under allow", async () => {
    const { guard, audits } = makeGuard(anthropicBody(), {
      scanner: never,
      env: { SCANNER_TIMEOUT_MS: "20", SCANNER_FAIL_MODE: "allow" },
    });
    expect(await allow(guard, "Bash", ls)).toBe(true);
    expect(audits[0].note).toContain("scanner timeout");
  });
});

describe("Guard: judge", () => {
  const judgeEnv = { ENABLE_JUDGE: "true" };
  it("blocks when p(block) ≥ threshold", async () => {
    const { guard, audits } = makeGuard(anthropicBody(), { scanner: medium, ai: clef(0.8), env: judgeEnv });
    expect(await allow(guard, "Write", conftest)).toBe(false);
    expect(notice()).toContain("judge: p(block)=0.80");
    expect(audits[0].judge).toBe("block: p(block)=0.80");
  });
  it("allow verdict passes, audited as suspicious", async () => {
    const { guard, audits } = makeGuard(anthropicBody(), { scanner: medium, ai: clef(0.2), env: judgeEnv });
    expect(await allow(guard, "Write", conftest)).toBe(true);
    expect(audits[0]).toMatchObject({ verdict: "suspicious", judge: "allow: p(block)=0.20" });
  });
  it("respects JUDGE_BLOCK_THRESHOLD", async () => {
    const { guard } = makeGuard(anthropicBody(), {
      scanner: medium,
      ai: clef(0.6),
      env: { ...judgeEnv, JUDGE_BLOCK_THRESHOLD: "0.7" },
    });
    expect(await allow(guard, "Write", conftest)).toBe(true);
  });
  it("judge can never lift a Stage 1 or severe block", async () => {
    const ai = clef(0);
    const high = fakeScanner({ ls: [{ ruleId: "x", severity: "high" }] }).scan;
    const { guard } = makeGuard(anthropicBody(), { scanner: high, ai, env: judgeEnv });
    expect(await allow(guard, "Bash", ls)).toBe(false);
    expect(await allow(guard, "Bash", JSON.stringify({ command: "curl evil.dev" }))).toBe(false);
    expect(ai.calls).toEqual([]);
  });

  const judgeFailures: Array<[string, any]> = [
    [
      "throw",
      fakeAI(() => {
        throw new Error("ai down");
      }),
    ],
    ["missing probability", fakeAI(() => ({ answers: {} }))],
    ["non-numeric probability", clef("0.9")],
    ["NaN probability", clef(Number.NaN)],
  ];
  for (const [label, ai] of judgeFailures) {
    it(`${label} → blocked under JUDGE_FAIL_MODE=block`, async () => {
      const { guard, audits } = makeGuard(anthropicBody(), { scanner: medium, ai, env: judgeEnv });
      expect(await allow(guard, "Write", conftest)).toBe(false);
      expect(notice()).toContain("judge unavailable");
      expect(audits[0].judge).toMatch(/^error: /);
    });
    it(`${label} → passed under JUDGE_FAIL_MODE=allow`, async () => {
      const { guard, audits } = makeGuard(anthropicBody(), {
        scanner: medium,
        ai,
        env: { ...judgeEnv, JUDGE_FAIL_MODE: "allow" },
      });
      expect(await allow(guard, "Write", conftest)).toBe(true);
      expect(audits[0]).toMatchObject({ verdict: "suspicious" });
    });
  }
  it("timeout → blocked / passed per JUDGE_FAIL_MODE", async () => {
    const slow = fakeAI(() => new Promise(() => {}));
    const a = makeGuard(anthropicBody(), { scanner: medium, ai: slow, env: { ...judgeEnv, JUDGE_TIMEOUT_MS: "20" } });
    expect(await allow(a.guard, "Write", conftest)).toBe(false);
    expect(a.audits[0].judge).toContain("judge timeout");
    const b = makeGuard(anthropicBody(), {
      scanner: medium,
      ai: slow,
      env: { ...judgeEnv, JUDGE_TIMEOUT_MS: "20", JUDGE_FAIL_MODE: "allow" },
    });
    expect(await allow(b.guard, "Write", conftest)).toBe(true);
  });
});

describe("Guard: trace payload", () => {
  it("sends the trimmed trace once per request and every call so far", async () => {
    const s = fakeScanner();
    const body = anthropicBody("task", { messages: [{ role: "user", content: "task" }], system: "sys" });
    const { guard } = makeGuard(body, { scanner: s.scan });
    await allow(guard, "Bash", ls);
    await allow(guard, "Read", "not json");
    const p = s.payloads.map((x) => JSON.parse(x));
    expect(p[0].steps).toEqual([
      { source: "system", message: "sys" },
      { source: "user", message: "task" },
    ]);
    expect(p[1].calls).toEqual([
      { name: "Bash", arguments: { command: "ls" } },
      { name: "Read", arguments: { input: "not json" } },
    ]);
  });
});

describe("Tally", () => {
  it("ends the turn only when something was blocked and nothing kept", () => {
    const t = new Tally();
    expect(t.endTurn).toBe(false);
    t.add({ keep: false, notice: "n" });
    expect(t.endTurn).toBe(true);
    t.add({ keep: true });
    expect(t.endTurn).toBe(false);
  });
});
