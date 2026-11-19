import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// No wrangler config: tests pass a hand-built env, since the real scanner binding is a Python Worker.
export default defineConfig({
  plugins: [
    cloudflareTest({
      miniflare: { compatibilityDate: "2026-11-01", compatibilityFlags: ["nodejs_compat"] },
    }),
  ],
  test: { include: ["test/**/*.test.ts"] },
});
