import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.ts";
import { findingSeverity, rank } from "../src/constants.ts";
import { scrub } from "../src/scrub.ts";
import { OFFICIAL } from "./helpers.ts";

describe("loadConfig", () => {
  it("defaults fail closed", () => {
    const c = loadConfig({ ...OFFICIAL, AI: {} });
    expect(c).toMatchObject({
      blockSeverity: "high",
      suspiciousAction: "block",
      scannerFailMode: "block",
      judgeFailMode: "block",
      judgeEnabled: true,
      judgeModel: "@cf/cloudflare/clef-flash",
      judgeBlockThreshold: 0.45,
      trustToolResults: false,
      denyServerTools: false,
      scannerTimeoutMs: 5000,
      judgeTimeoutMs: 15000,
      traceAgentSteps: 20,
      traceMaxResultChars: 2000,
    });
    expect(c.allowedHosts).toContain("registry.npmjs.org");
    expect(c.allowedHosts).toContain("example.org");
    expect(c.allowedHosts).not.toContain("github.com");
    expect(c.allowedHosts).not.toContain("huggingface.co");
  });

  it.each([
    ["BLOCK_SEVERITY", "severe"],
    ["SUSPICIOUS_ACTION", "warn"],
    ["SCANNER_FAIL_MODE", "open"],
    ["JUDGE_FAIL_MODE", "Block"],
    ["ENABLE_JUDGE", "yes"],
    ["TRUST_TOOL_RESULTS", "1"],
    ["SERVER_TOOLS", "block"],
    ["SCANNER_TIMEOUT_MS", "-1"],
    ["JUDGE_TIMEOUT_MS", "1.5"],
    ["TRACE_AGENT_STEPS", "0"],
    ["TRACE_MAX_RESULT_CHARS", "abc"],
    ["JUDGE_BLOCK_THRESHOLD", "0"],
    ["JUDGE_BLOCK_THRESHOLD", "1.2"],
  ])("rejects %s=%s", (k, v) => {
    expect(() => loadConfig({ ...OFFICIAL, [k]: v })).toThrow(`invalid ${k}`);
  });

  it("refuses non-official upstreams unless ALLOW_CUSTOM_UPSTREAM=true", () => {
    expect(() => loadConfig({ ...OFFICIAL, UPSTREAM_ANTHROPIC_URL: "https://evil.dev" })).toThrow(
      /UPSTREAM_ANTHROPIC_URL/,
    );
    expect(() => loadConfig({ ...OFFICIAL, UPSTREAM_OPENAI_URL: "https://api.openai.com/" })).toThrow(
      /UPSTREAM_OPENAI_URL/,
    );
    expect(() => loadConfig({ UPSTREAM_XAI_URL: "https://x.ai.evil.dev" })).toThrow(/UPSTREAM_XAI_URL/);
    expect(() => loadConfig({ UPSTREAM_GEMINI_URL: "https://evil.dev" })).toThrow(/UPSTREAM_GEMINI_URL/);
    expect(() =>
      loadConfig({
        UPSTREAM_ANTHROPIC_URL: "http://localhost:1",
        UPSTREAM_OPENAI_URL: "http://localhost:2",
        ALLOW_CUSTOM_UPSTREAM: "true",
      }),
    ).not.toThrow();
  });

  it("defaults every upstream to its official API", () => {
    expect(loadConfig({}).upstreams).toEqual({
      anthropic: "https://api.anthropic.com",
      openai: "https://api.openai.com",
      xai: "https://api.x.ai",
      gemini: "https://generativelanguage.googleapis.com",
    });
  });

  it("parses EXTRA_ALLOWED_HOSTS", () => {
    expect(loadConfig({ ...OFFICIAL, EXTRA_ALLOWED_HOSTS: " A.com,, b.org " }).allowedHosts.slice(-2)).toEqual([
      "a.com",
      "b.org",
    ]);
  });

  it("ranks severities; an unknown finding severity is critical", () => {
    expect(rank("low")).toBeLessThan(rank("medium"));
    expect(findingSeverity("bogus")).toBe("critical");
    expect(findingSeverity("low")).toBe("low");
  });
});

describe("scrub", () => {
  it.each([
    ["-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", "[REDACTED:private_key]"],
    ["sk-ant-api03-" + "a".repeat(30), "[REDACTED:anthropic_key]"],
    ["sk-proj-" + "a".repeat(30), "[REDACTED:openai_key]"],
    ["ghp_" + "a".repeat(36), "[REDACTED:github_token]"],
    ["hf_" + "a".repeat(34), "[REDACTED:hf_token]"],
    ["AKIAABCDEFGHIJKLMNOP", "[REDACTED:aws_key_id]"],
    ["xoxb-1234567890-abc", "[REDACTED:slack_token]"],
    ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlXzEyMw", "[REDACTED:jwt]"],
  ])("redacts %s", (secret, marker) => {
    const out = scrub(`before ${secret} after`);
    expect(out).toContain(marker);
    expect(out).not.toContain(secret);
  });
  it("redacts key=value secrets and auth headers, keeping the key", () => {
    expect(scrub("aws_secret_access_key = abc123SECRET")).toBe("aws_secret_access_key = [REDACTED]");
    expect(scrub("Authorization: Bearer abcdef123456")).toBe("Authorization: Bearer [REDACTED]");
    expect(scrub("password=hunter22")).toBe("password=[REDACTED]");
    expect(scrub("echo hello")).toBe("echo hello");
  });
});
