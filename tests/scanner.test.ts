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
  const { findings, packagesScanned } = await scanBunLockFile(
    resolve(fixtures, "bun-v1.lock"),
    await loadIndex(),
  );
  printFindings(`bun-v1.lock (clean) — ${packagesScanned} pkgs`, findings);
  expect(findings).toEqual([]);
  expect(packagesScanned).toBeGreaterThan(0);
});

test("scanPnpmLockFile parses pnpm lockfile v9 cleanly", async () => {
  const { findings, packagesScanned } = await scanPnpmLockFile(
    resolve(fixtures, "pnpm-lock-v9.yaml"),
    await loadIndex(),
  );
  printFindings(
    `pnpm-lock-v9.yaml (clean) — ${packagesScanned} pkgs`,
    findings,
  );
  expect(findings).toEqual([]);
  // This fixture is a truncated lockfile that only contains the `importers:`
  // block (no `packages:`), so packagesScanned is 0 — exercised separately by
  // the compromised pnpm fixture, which asserts the count.
});

test("scanYarnLockFile parses yarn berry v8 cleanly", async () => {
  const { findings, packagesScanned } = await scanYarnLockFile(
    resolve(fixtures, "yarn-v8.lock"),
    await loadIndex(),
  );
  printFindings(`yarn-v8.lock (clean) — ${packagesScanned} pkgs`, findings);
  expect(findings).toEqual([]);
  expect(packagesScanned).toBeGreaterThan(0);
});

// --- compromised fixtures: every parser must surface both planted hits

test("scanNpmLockFile detects compromised packages in package-lock.json v3", async () => {
  const file = resolve(compromisedDir, "package-lock.json");
  const result = await scanNpmLockFile(file, await loadIndex());
  const findings = sortByPackage(result.findings);
  printFindings(
    `package-lock.json v3 (compromised) — ${result.packagesScanned} pkgs`,
    findings,
  );
  expect(findings).toEqual(
    EXPECTED_HITS.map((h) => ({ ...h, lockfile: file, ecosystem: "npm" })),
  );
  expect(result.packagesScanned).toBe(3);
});

test("scanBunLockFile detects compromised packages in bun.lock", async () => {
  const file = resolve(compromisedDir, "bun.lock");
  const result = await scanBunLockFile(file, await loadIndex());
  const findings = sortByPackage(result.findings);
  printFindings(
    `bun.lock (compromised) — ${result.packagesScanned} pkgs`,
    findings,
  );
  expect(findings).toEqual(
    EXPECTED_HITS.map((h) => ({ ...h, lockfile: file, ecosystem: "bun" })),
  );
  expect(result.packagesScanned).toBe(3);
});

test("scanPnpmLockFile detects compromised packages in pnpm-lock.yaml v9", async () => {
  const file = resolve(compromisedDir, "pnpm-lock.yaml");
  const result = await scanPnpmLockFile(file, await loadIndex());
  const findings = sortByPackage(result.findings);
  printFindings(
    `pnpm-lock.yaml v9 (compromised) — ${result.packagesScanned} pkgs`,
    findings,
  );
  expect(findings).toEqual(
    EXPECTED_HITS.map((h) => ({ ...h, lockfile: file, ecosystem: "pnpm" })),
  );
  expect(result.packagesScanned).toBe(3);
});

test("scanYarnLockFile detects compromised packages in yarn.lock berry v8", async () => {
  const file = resolve(compromisedDir, "yarn.lock");
  const result = await scanYarnLockFile(file, await loadIndex());
  const findings = sortByPackage(result.findings);
  printFindings(
    `yarn.lock berry v8 (compromised) — ${result.packagesScanned} pkgs`,
    findings,
  );
  expect(findings).toEqual(
    EXPECTED_HITS.map((h) => ({ ...h, lockfile: file, ecosystem: "yarn" })),
  );
  expect(result.packagesScanned).toBe(3);
});

// --- end-to-end: scanLockFiles discovers every standard lockfile and tags
// findings with their relative path. Each fixture plants the same 2 hits, so
// we expect 4 lockfiles * 2 hits = 8 findings total.
test("scanLockFiles discovers all four compromised lockfiles and aggregates findings", async () => {
  const result = await scanLockFiles(compromisedDir, await loadDb());

  console.log(
    `\n[scanLockFiles] scanned ${result.scannedFiles.length} lockfile(s): ${result.scannedFiles.join(", ")}`,
  );
  console.log(
    `[scanLockFiles] ${result.packagesScanned} packages · ${result.packagesScanned - result.findings.length} clean · ${result.findings.length} affected`,
  );
  printFindings("scanLockFiles aggregate", result.findings);

  expect(result.errors).toEqual([]);
  expect(result.packagesScanned).toBe(12); // 4 lockfiles × 3 packages each
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
