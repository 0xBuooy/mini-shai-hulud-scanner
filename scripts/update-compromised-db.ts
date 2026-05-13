/**
 * Crawls the Snyk advisory for the TanStack "mini Shai-Hulud" npm supply-chain
 * compromise (May 2026) and writes a normalized compromised-db.json.
 *
 * Implementation note on "pagination":
 * The advisory page (security.snyk.io is a Nuxt SPA) renders only 30 rows of
 * 172 in the server-side HTML and paginates the rest entirely client-side.
 * `?page=N` is ignored by the server. The full dataset, however, is shipped
 * inline in a single JS chunk as a `JSON.parse('[...]')` literal. So instead
 * of trying to scrape paginated HTML, we:
 *
 *   1. Fetch the advisory page.
 *   2. Enumerate every `_nuxt/*.js` chunk it preloads (i.e. all "pages" of
 *      app code, including the route component for this advisory).
 *   3. Look in each chunk for the embedded `JSON.parse('[...]')` array whose
 *      entries have package_name + vulnerable fields.
 *   4. Normalize and write compromised-db.json.
 */
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { CompromisedDb, CompromisedPackage } from "../src/types.ts";

const ADVISORY_SLUG = "TanStack-npm-Supply-Chain-Compromise-May-2026";
const ADVISORY_URL = `https://security.snyk.io/${ADVISORY_SLUG}`;
const OUTPUT_PATH = resolve(import.meta.dir, "..", "compromised-db.json");
const UA = "mini-shai-hulud-scanner/0.1 (+https://github.com/0xbuooy)";

type SnykRow = {
  public_id: string;
  vulnerable: string;
  package_name: string;
  versions_found?: string;
};

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, { headers: { "user-agent": UA } });
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return res.text();
}

function extractChunkPaths(html: string): string[] {
  const paths = new Set<string>();
  // <link rel="modulepreload" ... href="/_nuxt/X.js">
  for (const m of html.matchAll(/href="(\/_nuxt\/[^"]+\.js)"/g)) {
    paths.add(m[1]!);
  }
  // <script ... src="/_nuxt/X.js">
  for (const m of html.matchAll(/src="(\/_nuxt\/[^"]+\.js)"/g)) {
    paths.add(m[1]!);
  }
  return [...paths];
}

/**
 * Find a `JSON.parse('[...]')` array in chunk source whose entries look like
 * Snyk advisory rows. The argument is single-quoted JSON, so unescape `\'`.
 */
function extractSnykRowsFromChunk(js: string): SnykRow[] | null {
  const re = /JSON\.parse\('(\[(?:\\.|[^'\\])*\])'\)/g;
  for (const m of js.matchAll(re)) {
    const literal = m[1]!.replace(/\\'/g, "'").replace(/\\\\/g, "\\");
    let parsed: unknown;
    try {
      parsed = JSON.parse(literal);
    } catch {
      continue;
    }
    if (
      Array.isArray(parsed) &&
      parsed.length > 0 &&
      parsed.every(
        (r): r is SnykRow =>
          typeof r === "object" &&
          r !== null &&
          "package_name" in r &&
          "vulnerable" in r &&
          "public_id" in r,
      )
    ) {
      return parsed;
    }
  }
  return null;
}

/**
 * Snyk encodes the affected version set as `{=1.2.3,=1.2.4}` (each `=X.Y.Z`
 * is one exact pinned compromised version). Convert to a deduped string[].
 */
function parseVulnerableVersions(spec: string): string[] {
  const inner = spec.replace(/^\{|\}$/g, "");
  if (!inner) return [];
  const versions = new Set<string>();
  for (const part of inner.split(",")) {
    const v = part.trim().replace(/^=/, "").trim();
    if (v) versions.add(v);
  }
  return [...versions].sort();
}

function normalize(rows: SnykRow[]): CompromisedPackage[] {
  return rows
    .map((r) => ({
      name: r.package_name,
      ecosystem: "npm" as const,
      versions: parseVulnerableVersions(r.vulnerable),
      snykId: r.public_id,
      snykUrl: `https://security.snyk.io/vuln/${r.public_id}`,
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

async function main(): Promise<void> {
  console.log(`fetching ${ADVISORY_URL}`);
  const html = await fetchText(ADVISORY_URL);

  const chunks = extractChunkPaths(html);
  console.log(`scanning ${chunks.length} chunks for embedded advisory data`);

  let rows: SnykRow[] | null = null;
  for (const path of chunks) {
    const chunkUrl = `https://security.snyk.io${path}`;
    let js: string;
    try {
      js = await fetchText(chunkUrl);
    } catch (err) {
      console.warn(`  skip ${path}: ${(err as Error).message}`);
      continue;
    }
    const found = extractSnykRowsFromChunk(js);
    if (found) {
      console.log(`  found ${found.length} rows in ${path}`);
      rows = found;
      break;
    }
  }

  if (!rows) {
    throw new Error(
      "Could not locate the embedded advisory data in any chunk. " +
        "Snyk may have changed the page; inspect the chunk that imports " +
        "JSON.parse('[{\"public_id\":...}]') and adjust the extractor.",
    );
  }

  const packages = normalize(rows);
  const db: CompromisedDb = {
    source: ADVISORY_URL,
    incident: ADVISORY_SLUG,
    fetchedAt: new Date().toISOString(),
    totalPackages: packages.length,
    packages,
  };

  await writeFile(OUTPUT_PATH, JSON.stringify(db, null, 2) + "\n");
  console.log(`wrote ${packages.length} packages -> ${OUTPUT_PATH}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
