import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import pc from "picocolors";
import { scanLockFiles } from "./scanner.ts";
import type { CompromisedDb, Finding } from "./types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(process.argv[2] ?? process.cwd());
const dbPath = resolve(
  process.argv[3] ?? resolve(here, "..", "compromised-db.json"),
);

const db = JSON.parse(await readFile(dbPath, "utf8")) as CompromisedDb;
const result = await scanLockFiles(root, db);

// OSC-8 hyperlink: clickable in iTerm2, WezTerm, modern Terminal.app, etc.
// In dumb terminals the escape codes vanish and only the visible text is shown.
function link(url: string, text: string): string {
  if (!process.stdout.isTTY) return text;
  return `\x1b]8;;${url}\x1b\\${text}\x1b]8;;\x1b\\`;
}

console.log(pc.bold("mini-shai-hulud-scanner"));
console.log(`  ${pc.dim("root:")} ${root}`);
console.log(
  `  ${pc.dim("db:  ")} ${dbPath} ${pc.dim(`· ${db.totalPackages} known compromised versions`)}`,
);
console.log();

console.log(
  `scanned ${pc.bold(String(result.scannedFiles.length))} lockfile(s):`,
);
for (const f of result.scannedFiles) console.log(`  ${pc.dim("·")} ${f}`);

if (result.errors.length > 0) {
  console.log();
  console.log(pc.yellow(`⚠ ${result.errors.length} parse error(s):`));
  for (const e of result.errors) {
    console.log(`  ${pc.yellow(e.file)}: ${e.error}`);
  }
}

if (result.findings.length === 0) {
  console.log();
  console.log(pc.green("✓ no compromised packages found"));
  process.exit(0);
}

const byLockfile = new Map<string, Finding[]>();
for (const f of result.findings) {
  const arr = byLockfile.get(f.lockfile) ?? [];
  arr.push(f);
  byLockfile.set(f.lockfile, arr);
}

const pkgWidth = Math.max(
  ...result.findings.map((f) => `${f.package}@${f.version}`.length),
);
const ecoWidth = Math.max(...result.findings.map((f) => f.ecosystem.length));

console.log();
console.log(
  pc.red(
    pc.bold(
      `⚠ ${result.findings.length} compromised package(s) found across ${byLockfile.size} lockfile(s)`,
    ),
  ),
);

for (const [file, hits] of byLockfile) {
  console.log();
  console.log(`  ${pc.bold(file)}`);
  for (const h of hits) {
    const spec = `${h.package}@${h.version}`.padEnd(pkgWidth);
    const eco = h.ecosystem.padEnd(ecoWidth);
    console.log(
      `    ${pc.red("✗")} ${pc.bold(spec)}  ${pc.dim(eco)}  ${pc.cyan(link(h.snykUrl, h.snykId))}`,
    );
  }
}

console.log();
console.log(
  pc.dim(
    "  Each Snyk ID is a clickable link in supported terminals. Bump to a safe version and rotate any credentials exposed on the install machine.",
  ),
);
process.exit(1);
