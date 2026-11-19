/**
 * Scrubs a scripts/record.ts capture (home dir, username, temp paths, secrets, request.metadata) and
 * writes it gzipped to scanner/test/recorded/<name>.jsonl.gz; exits non-zero if a --forbid string remains.
 *
 *   node scripts/record-finish.ts <in.jsonl> <name> [--replace FROM=TO ...] [--forbid STR ...]
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { gzipSync } from "node:zlib";
import { scrub } from "../src/scrub.ts";

const [input, name, ...rest] = process.argv.slice(2);
if (!input || !name) {
  console.error("usage: record-finish.ts <in.jsonl> <name> [--replace FROM=TO ...] [--forbid STRING ...]");
  process.exit(2);
}
const replacements: Array<[string | RegExp, string]> = [];
const forbid: string[] = [];
for (let i = 0; i < rest.length; i++) {
  if (rest[i] === "--replace") {
    const [from, to] = rest[++i].split("=");
    replacements.push([from, to]);
  } else if (rest[i] === "--forbid") forbid.push(rest[++i]);
}
const user = userInfo().username;
replacements.push(
  [/\/private\/tmp\/[^\s"'\\]*?\/runs\/\d+/g, "/home/dev/repo"],
  [/\/(?:private\/)?(?:tmp|var\/folders)\/[^\s"'\\]*/g, "/tmp/x"],
  [homedir(), "/home/dev"],
  [new RegExp(`\\b${user}\\b`, "g"), "dev"],
);

let text = readFileSync(input, "utf8");
for (const [from, to] of replacements)
  text = typeof from === "string" ? text.split(from).join(to) : text.replace(from, to);
const lines = text
  .split("\n")
  .filter(Boolean)
  .map((l) => {
    // Scrub string values (not the JSON text) so escaping stays valid.
    const item = JSON.parse(l);
    // metadata.user_id holds device/account ids; the guard never reads it.
    if (item?.request && typeof item.request === "object") delete item.request.metadata;
    return JSON.stringify(item, (_k, v) => (typeof v === "string" ? scrub(v) : v));
  });
const out = lines.join("\n") + "\n";
for (const f of forbid) {
  if (out.includes(f)) {
    console.error(`forbidden string still present: ${f.slice(0, 4)}…`);
    process.exit(1);
  }
}
const dir = new URL("../../scanner/test/recorded/", import.meta.url).pathname;
mkdirSync(dir, { recursive: true });
writeFileSync(`${dir}${name}.jsonl.gz`, gzipSync(out));
console.log(`${lines.length} recorded requests → ${dir}${name}.jsonl.gz (${(out.length / 1e6).toFixed(1)} MB raw)`);
