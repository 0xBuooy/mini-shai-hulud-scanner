import { readdir, readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import type {
  CompromisedDb,
  CompromisedIndex,
  Ecosystem,
  Finding,
  ScanError,
  ScanResult,
} from "./types.ts";

const LOCK_FILENAMES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "bun.lock",
  "bun.lockb",
  "pnpm-lock.yaml",
  "yarn.lock",
]);

export function buildIndex(db: CompromisedDb): CompromisedIndex {
  const idx: CompromisedIndex = new Map();
  for (const p of db.packages) {
    let vers = idx.get(p.name);
    if (!vers) {
      vers = new Map();
      idx.set(p.name, vers);
    }
    for (const v of p.versions) {
      vers.set(v, { snykId: p.snykId, snykUrl: p.snykUrl });
    }
  }
  return idx;
}

function hit(
  index: CompromisedIndex,
  name: string,
  version: string,
): { snykId: string; snykUrl: string } | null {
  return index.get(name)?.get(version) ?? null;
}

function record(
  out: Finding[],
  lockfile: string,
  ecosystem: Ecosystem,
  name: string,
  version: string,
  h: { snykId: string; snykUrl: string },
): void {
  out.push({ lockfile, ecosystem, package: name, version, ...h });
}

/**
 * Discover every supported lockfile under `root` (skipping node_modules) and
 * scan them concurrently. Per-file errors do not abort the overall scan.
 */
export async function scanLockFiles(
  root: string,
  db: CompromisedDb,
): Promise<ScanResult> {
  const index = buildIndex(db);
  const files = await findLockfiles(root);

  const results = await Promise.all(
    files.map(
      async (
        rel,
      ): Promise<{ findings: Finding[]; error: ScanError | null }> => {
        const abs = resolve(root, rel);
        const name = basename(rel);
        try {
          let found: Finding[];
          if (name === "package-lock.json" || name === "npm-shrinkwrap.json") {
            found = await scanNpmLockFile(abs, index);
          } else if (name === "bun.lock" || name === "bun.lockb") {
            found = await scanBunLockFile(abs, index);
          } else if (name === "pnpm-lock.yaml") {
            found = await scanPnpmLockFile(abs, index);
          } else if (name === "yarn.lock") {
            found = await scanYarnLockFile(abs, index);
          } else {
            return { findings: [], error: null };
          }
          return {
            findings: found.map((f) => ({ ...f, lockfile: rel })),
            error: null,
          };
        } catch (err) {
          return {
            findings: [],
            error: { file: rel, error: (err as Error).message },
          };
        }
      },
    ),
  );

  return {
    scannedFiles: files,
    findings: results.flatMap((r) => r.findings),
    errors: results.flatMap((r) => (r.error ? [r.error] : [])),
  };
}

/**
 * Recursive lockfile walker. Skips `node_modules` and dot-directories so that
 * vendored lockfiles inside dependency trees, `.git`, `.next`, etc. don't
 * pollute the scan. Works under both Bun and Node — no platform-specific glob.
 */
async function findLockfiles(root: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(dir: string, rel: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (ent.name === "node_modules" || ent.name.startsWith(".")) continue;
      const subRel = rel ? `${rel}/${ent.name}` : ent.name;
      const subAbs = join(dir, ent.name);
      if (ent.isDirectory()) {
        await walk(subAbs, subRel);
      } else if (ent.isFile() && LOCK_FILENAMES.has(ent.name)) {
        out.push(subRel);
      }
    }
  }
  await walk(root, "");
  return out;
}

// -------------------------------------------------------------------------- npm

type NpmV1Dep = {
  version?: string;
  dependencies?: Record<string, NpmV1Dep>;
};

type NpmLockJson = {
  lockfileVersion?: number;
  packages?: Record<
    string,
    { version?: string; name?: string; link?: boolean } | undefined
  >;
  dependencies?: Record<string, NpmV1Dep>;
};

/**
 * Scans `package-lock.json` / `npm-shrinkwrap.json`. Handles all three known
 * lockfileVersion shapes:
 *   - v1: nested `dependencies` tree only
 *   - v2: both `packages` (path-keyed) and `dependencies`
 *   - v3: `packages` only
 *
 * v2/v3 uses keys like `node_modules/foo` or
 * `node_modules/parent/node_modules/@scope/foo`. The real package name is the
 * substring after the final `node_modules/` segment (or `info.name` for
 * aliases / workspace links).
 */
export async function scanNpmLockFile(
  file: string,
  index: CompromisedIndex,
): Promise<Finding[]> {
  const data = JSON.parse(await readFile(file, "utf8")) as NpmLockJson;
  const findings: Finding[] = [];

  if (data.packages) {
    for (const [path, info] of Object.entries(data.packages)) {
      if (!info || path === "") continue;
      if (info.link) continue;
      const version = info.version;
      if (!version) continue;
      const marker = "node_modules/";
      const tail =
        path.lastIndexOf(marker) >= 0
          ? path.slice(path.lastIndexOf(marker) + marker.length)
          : path;
      const name = info.name ?? tail;
      const h = hit(index, name, version);
      if (h) record(findings, file, "npm", name, version, h);
    }
  } else if (data.dependencies) {
    walkV1(data.dependencies, (name, version) => {
      const h = hit(index, name, version);
      if (h) record(findings, file, "npm", name, version, h);
    });
  }

  return findings;
}

function walkV1(
  deps: Record<string, NpmV1Dep>,
  visit: (name: string, version: string) => void,
): void {
  for (const [name, dep] of Object.entries(deps)) {
    if (dep.version) visit(name, dep.version);
    if (dep.dependencies) walkV1(dep.dependencies, visit);
  }
}

// -------------------------------------------------------------------------- bun

/**
 * Scans `bun.lock` (text, JSONC) for compromised packages.
 *
 * `bun.lockb` is a legacy binary format and is not parsed here — the function
 * throws a clear instruction to convert it.
 *
 * `bun.lock` shape (any lockfileVersion to date):
 *   {
 *     "packages": {
 *       "<key>": ["name@version", "registry-data", { ... }, "integrity"],
 *       ...
 *     }
 *   }
 * The first element of each value array is always the resolved `name@version`.
 */
export async function scanBunLockFile(
  file: string,
  index: CompromisedIndex,
): Promise<Finding[]> {
  if (file.endsWith(".lockb")) {
    throw new Error(
      "bun.lockb (binary) is not supported — run `bun install --save-text-lockfile` to produce bun.lock",
    );
  }

  const text = await readFile(file, "utf8");
  const data = parseJsonc(text) as { packages?: Record<string, unknown> };
  const findings: Finding[] = [];
  const packages = data.packages;
  if (!packages) return findings;

  for (const value of Object.values(packages)) {
    if (!Array.isArray(value) || value.length === 0) continue;
    const head = value[0];
    if (typeof head !== "string") continue;
    const parsed = splitNameVersion(head);
    if (!parsed) continue;
    const h = hit(index, parsed.name, parsed.version);
    if (h) record(findings, file, "bun", parsed.name, parsed.version, h);
  }
  return findings;
}

function splitNameVersion(
  spec: string,
): { name: string; version: string } | null {
  const at = spec.lastIndexOf("@");
  if (at <= 0) return null;
  const name = spec.slice(0, at);
  const version = spec.slice(at + 1);
  if (!name || !version) return null;
  return { name, version };
}

/**
 * Bun writes JSONC: line/block comments and trailing commas are permitted.
 * Parsed with a tiny state machine so that `//` and `/*` inside JSON strings
 * (e.g. base64 sha512 integrity values like `sha512-.../...==`) are preserved.
 */
function parseJsonc(text: string): unknown {
  let out = "";
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i]!;
    if (c === '"') {
      // copy string literal verbatim, honoring backslash escapes
      const start = i;
      i++;
      while (i < n) {
        const d = text[i]!;
        if (d === "\\") {
          i += 2;
          continue;
        }
        if (d === '"') {
          i++;
          break;
        }
        i++;
      }
      out += text.slice(start, i);
      continue;
    }
    if (c === "/" && i + 1 < n) {
      const next = text[i + 1]!;
      if (next === "/") {
        i += 2;
        while (i < n && text[i] !== "\n") i++;
        continue;
      }
      if (next === "*") {
        i += 2;
        while (i + 1 < n && !(text[i] === "*" && text[i + 1] === "/")) i++;
        i += 2;
        continue;
      }
    }
    out += c;
    i++;
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
}

// ------------------------------------------------------------------------- pnpm

/**
 * Scans `pnpm-lock.yaml`. Reads only the `packages:` block; supported key
 * shapes across lockfile versions:
 *   v5:  `/foo/1.2.3` or `/@scope/foo/1.2.3`
 *   v6:  `/foo@1.2.3` or `/@scope/foo@1.2.3`
 *   v9:  `foo@1.2.3`  or `@scope/foo@1.2.3` (no leading slash, may be quoted)
 * Any peer-dep suffix `(peer@x)` is ignored.
 *
 * Parsed line-by-line rather than via a YAML library to keep the scanner
 * dependency-free; only flat scalar keys are needed.
 */
export async function scanPnpmLockFile(
  file: string,
  index: CompromisedIndex,
): Promise<Finding[]> {
  const text = await readFile(file, "utf8");
  const findings: Finding[] = [];

  const lines = text.split("\n");
  let inPackages = false;
  for (const line of lines) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
      continue;
    }
    if (!inPackages) continue;
    // A new top-level key terminates the packages: section.
    if (/^\S/.test(line)) break;

    // Match only the entry header lines (indented by exactly 2 spaces, ending in `:`).
    const m = line.match(
      /^ {2}'?\/?(@[^/]+\/[^/@'\s]+|[^/@'\s]+)[@/]([^:'(\s]+)'?\s*:\s*$/,
    );
    if (!m) continue;
    const name = m[1]!;
    const version = m[2]!;
    const h = hit(index, name, version);
    if (h) record(findings, file, "pnpm", name, version, h);
  }

  return findings;
}

// ------------------------------------------------------------------------- yarn

/**
 * Scans `yarn.lock` for both yarn classic (v1) and yarn berry (v2+).
 *
 * Both formats are block-structured: a header line listing one or more
 * descriptors (`"foo@^1", "foo@^1.2":` or `"foo@npm:^1.2":`) followed by an
 * indented body containing `version "1.2.3"` (v1) or `version: 1.2.3` (berry).
 *
 * We extract the package name from each descriptor (`name@range`, splitting on
 * the last `@`) and check it against the resolved version.
 */
export async function scanYarnLockFile(
  file: string,
  index: CompromisedIndex,
): Promise<Finding[]> {
  const text = await readFile(file, "utf8");
  const findings: Finding[] = [];

  const blocks = text.split(/\r?\n\r?\n+/);
  for (const block of blocks) {
    const lines = block
      .split(/\r?\n/)
      .filter((l) => l.length > 0 && !l.startsWith("#"));
    if (lines.length === 0) continue;

    const header = lines[0];
    if (!header || !header.endsWith(":")) continue;

    const versionLine = lines.find((l) => /^\s+version[:\s]/.test(l));
    if (!versionLine) continue;
    const vm = versionLine.match(/version[:\s]+"?([^"\s]+)"?/);
    if (!vm) continue;
    const version = vm[1]!;

    const headerKeys = header.slice(0, -1).trim().split(/,\s*/);
    const names = new Set<string>();
    for (const raw of headerKeys) {
      const k = raw.replace(/^"|"$/g, "");
      const at = k.lastIndexOf("@");
      if (at <= 0) continue;
      names.add(k.slice(0, at));
    }

    for (const name of names) {
      const h = hit(index, name, version);
      if (h) record(findings, file, "yarn", name, version, h);
    }
  }

  return findings;
}
