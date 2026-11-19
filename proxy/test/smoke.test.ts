import { describe, expect, it } from "vitest";

describe("runtime", () => {
  it("runs inside workerd", () => {
    expect(navigator.userAgent).toBe("Cloudflare-Workers");
    expect(typeof (crypto.subtle as any).timingSafeEqual).toBe("function");
  });
});
