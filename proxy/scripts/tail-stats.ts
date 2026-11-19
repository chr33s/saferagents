/**
 * Summarizes `wrangler tail --format json` output into CPU/wall-time percentiles per Worker and session label (§7).
 *
 *   node scripts/tail-stats.ts <tail.jsonl> [sinceEpochMs]
 */
import { readFileSync } from "node:fs";
import { pct } from "./stats.ts";

const [file, since] = process.argv.slice(2);
const raw = readFileSync(file, "utf8");
// Tail prints pretty-printed objects, each closed by a "}" line.
const events: any[] = raw
  .split(/^}$/m)
  .filter((chunk) => chunk.trim())
  .map((chunk) => JSON.parse(`${chunk}}`));

const groups = new Map<string, { cpu: number[]; wall: number[] }>();
for (const e of events) {
  if (since && e.eventTimestamp < Number(since)) continue;
  const session = e.event?.request?.headers?.["x-session-id"] as string | undefined;
  const label = `${e.scriptName}${e.event?.rpcMethod ? `.${e.event.rpcMethod}` : ""}${session ? ` [${session.replace(/-\d+$/, "")}]` : ""}`;
  const g = groups.get(label) ?? { cpu: [], wall: [] };
  g.cpu.push(e.cpuTime);
  g.wall.push(e.wallTime);
  groups.set(label, g);
}
for (const [label, g] of [...groups].sort()) {
  console.log(
    `${label}: n=${g.cpu.length} cpu p50 ${pct(g.cpu, 50)} / p95 ${pct(g.cpu, 95)} / max ${Math.max(...g.cpu)} ms; wall p50 ${pct(g.wall, 50)} / p95 ${pct(g.wall, 95)} ms`,
  );
}
