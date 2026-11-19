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
// The listing body is optional (an empty fence), and its closing fence must start a line.
const LISTING = /(<!-- source: ([\w./-]+) -->\n```\w*\n)(?:[\s\S]*?\n)??```/g;
const synced = spec.replace(
  LISTING,
  (_, open: string, path: string) => `${open}${readFileSync(join(root, path), "utf8").trimEnd()}\n\`\`\``,
);
const markers = spec.match(/<!-- source: [\w./-]+ -->/g)?.length ?? 0;
if ((synced.match(LISTING)?.length ?? 0) !== markers) {
  console.error("spec.md: every <!-- source: … --> marker needs a fenced listing right after it");
  process.exit(1);
}
if (!process.argv.includes("--check")) writeFileSync(specPath, synced);
else if (synced !== spec) {
  console.error("spec.md listings are stale: run `mise run spec`");
  process.exit(1);
}
