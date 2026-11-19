/**
 * Refreshes spec.md code listings from the files they name (`<!-- source: path -->` above a fence).
 *
 *   node scripts/spec-sync.ts [--check]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dirname, "../..");
const specPath = join(root, "spec.md");
const spec = readFileSync(specPath, "utf8");
const synced = spec.replace(
  /(<!-- source: (\S+) -->\n```\w*\n)[\s\S]*?(\n```)/g,
  (_, open: string, path: string, close: string) => open + readFileSync(join(root, path), "utf8").trimEnd() + close,
);
if (!process.argv.includes("--check")) writeFileSync(specPath, synced);
else if (synced !== spec) {
  console.error("spec.md listings are stale: run `mise run spec`");
  process.exit(1);
}
