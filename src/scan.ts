import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scanLockFiles } from "./scanner.ts";
import type { CompromisedDb } from "./types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(process.argv[2] ?? process.cwd());
const dbPath = resolve(
  process.argv[3] ?? resolve(here, "..", "compromised-db.json"),
);

const db = JSON.parse(await readFile(dbPath, "utf8")) as CompromisedDb;
const result = await scanLockFiles(root, db);

console.log(`root: ${root}`);
console.log(`db:   ${dbPath} (${db.totalPackages} compromised packages)`);
console.log(`scanned ${result.scannedFiles.length} lock file(s):`);
for (const f of result.scannedFiles) console.log(`  - ${f}`);

if (result.errors.length > 0) {
  console.log(`\nerrors:`);
  for (const e of result.errors) console.log(`  ${e.file}: ${e.error}`);
}

if (result.findings.length === 0) {
  console.log(`\nno compromised packages found`);
  process.exit(0);
}

console.log(`\n${result.findings.length} compromised package(s) found:\n`);
for (const f of result.findings) {
  console.log(`  ${f.package}@${f.version}  [${f.ecosystem}]  ${f.snykId}`);
  console.log(`    in ${f.lockfile}`);
  console.log(`    ${f.snykUrl}`);
}
process.exit(1);
