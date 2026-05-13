import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildIndex,
  scanBunLockFile,
  scanLockFiles,
  scanNpmLockFile,
  scanPnpmLockFile,
  scanYarnLockFile,
} from "../src/scanner.ts";
import type {
  CompromisedDb,
  CompromisedIndex,
  Finding,
} from "../src/types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = resolve(here, "fixtures");
const compromisedDir = resolve(fixtures, "compromised");

let cachedDb: CompromisedDb | null = null;
let cachedIndex: CompromisedIndex | null = null;
async function loadDb(): Promise<CompromisedDb> {
  if (cachedDb) return cachedDb;
  cachedDb = JSON.parse(
    await readFile(resolve(here, "..", "compromised-db.json"), "utf8"),
  ) as CompromisedDb;
  return cachedDb;
}
async function loadIndex(): Promise<CompromisedIndex> {
  if (cachedIndex) return cachedIndex;
  cachedIndex = buildIndex(await loadDb());
  return cachedIndex;
}

// Two real entries from the bundled compromised DB, embedded in each
// hand-crafted compromised fixture under tests/fixtures/compromised/.
const EXPECTED_HITS = [
  {
    package: "@beproduct/nestjs-auth",
    version: "0.1.10",
    snykId: "SNYK-JS-BEPRODUCTNESTJSAUTH-16640335",
    snykUrl:
      "https://security.snyk.io/vuln/SNYK-JS-BEPRODUCTNESTJSAUTH-16640335",
  },
  {
    package: "@dirigible-ai/sdk",
    version: "0.6.2",
    snykId: "SNYK-JS-DIRIGIBLEAISDK-16640337",
    snykUrl: "https://security.snyk.io/vuln/SNYK-JS-DIRIGIBLEAISDK-16640337",
  },
] as const;

function sortByPackage(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => a.package.localeCompare(b.package));
}

function printFindings(label: string, findings: Finding[]): void {
  console.log(`\n[${label}] ${findings.length} finding(s)`);
  if (findings.length === 0) {
    console.log("  (clean — no compromised packages)");
    return;
  }
  for (const f of findings) {
    console.log(
      `  ${f.package}@${f.version}  [${f.ecosystem}]  ${f.snykId}\n    in ${f.lockfile}\n    ${f.snykUrl}`,
    );
  }
}

// --- clean fixtures: parsers handle real-world lockfiles without false positives

test("scanBunLockFile parses bun lockfileVersion 1 cleanly", async () => {
  const findings = await scanBunLockFile(
    resolve(fixtures, "bun-v1.lock"),
    await loadIndex(),
  );
  printFindings("bun-v1.lock (clean)", findings);
  expect(findings).toEqual([]);
});

test("scanPnpmLockFile parses pnpm lockfile v9 cleanly", async () => {
  const findings = await scanPnpmLockFile(
    resolve(fixtures, "pnpm-lock-v9.yaml"),
    await loadIndex(),
  );
  printFindings("pnpm-lock-v9.yaml (clean)", findings);
  expect(findings).toEqual([]);
});

test("scanYarnLockFile parses yarn berry v8 cleanly", async () => {
  const findings = await scanYarnLockFile(
    resolve(fixtures, "yarn-v8.lock"),
    await loadIndex(),
  );
  printFindings("yarn-v8.lock (clean)", findings);
  expect(findings).toEqual([]);
});

// --- compromised fixtures: every parser must surface both planted hits

test("scanNpmLockFile detects compromised packages in package-lock.json v3", async () => {
  const file = resolve(compromisedDir, "package-lock.json");
  const findings = sortByPackage(
    await scanNpmLockFile(file, await loadIndex()),
  );
  printFindings("package-lock.json v3 (compromised)", findings);
  expect(findings).toEqual(
    EXPECTED_HITS.map((h) => ({ ...h, lockfile: file, ecosystem: "npm" })),
  );
});

test("scanBunLockFile detects compromised packages in bun.lock", async () => {
  const file = resolve(compromisedDir, "bun.lock");
  const findings = sortByPackage(
    await scanBunLockFile(file, await loadIndex()),
  );
  printFindings("bun.lock (compromised)", findings);
  expect(findings).toEqual(
    EXPECTED_HITS.map((h) => ({ ...h, lockfile: file, ecosystem: "bun" })),
  );
});

test("scanPnpmLockFile detects compromised packages in pnpm-lock.yaml v9", async () => {
  const file = resolve(compromisedDir, "pnpm-lock.yaml");
  const findings = sortByPackage(
    await scanPnpmLockFile(file, await loadIndex()),
  );
  printFindings("pnpm-lock.yaml v9 (compromised)", findings);
  expect(findings).toEqual(
    EXPECTED_HITS.map((h) => ({ ...h, lockfile: file, ecosystem: "pnpm" })),
  );
});

test("scanYarnLockFile detects compromised packages in yarn.lock berry v8", async () => {
  const file = resolve(compromisedDir, "yarn.lock");
  const findings = sortByPackage(
    await scanYarnLockFile(file, await loadIndex()),
  );
  printFindings("yarn.lock berry v8 (compromised)", findings);
  expect(findings).toEqual(
    EXPECTED_HITS.map((h) => ({ ...h, lockfile: file, ecosystem: "yarn" })),
  );
});

// --- end-to-end: scanLockFiles discovers every standard lockfile and tags
// findings with their relative path. Each fixture plants the same 2 hits, so
// we expect 4 lockfiles * 2 hits = 8 findings total.
test("scanLockFiles discovers all four compromised lockfiles and aggregates findings", async () => {
  const result = await scanLockFiles(compromisedDir, await loadDb());

  console.log(
    `\n[scanLockFiles] scanned ${result.scannedFiles.length} lockfile(s): ${result.scannedFiles.join(", ")}`,
  );
  printFindings("scanLockFiles aggregate", result.findings);

  expect(result.errors).toEqual([]);
  expect([...result.scannedFiles].sort()).toEqual([
    "bun.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
  ]);
  expect(result.findings).toHaveLength(8);

  const byLockfile = new Map<string, Finding[]>();
  for (const f of result.findings) {
    const arr = byLockfile.get(f.lockfile) ?? [];
    arr.push(f);
    byLockfile.set(f.lockfile, arr);
  }
  for (const file of [
    "bun.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
  ]) {
    const hits = sortByPackage(byLockfile.get(file) ?? []);
    expect(hits.map((h) => `${h.package}@${h.version}`)).toEqual([
      "@beproduct/nestjs-auth@0.1.10",
      "@dirigible-ai/sdk@0.6.2",
    ]);
  }
});
