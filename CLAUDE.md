# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Bun is the dev runtime (the published artifact runs under Node ≥18).

- `bun test` — run the test suite (`bun:test`).
- `bun test tests/scanner.test.ts -t "pnpm v9"` — run a single test by name pattern.
- `bun run scan [root] [dbPath]` — run the scanner against a directory (defaults: cwd, `./compromised-db.json`).
- `bun run update-db` — re-fetch the Snyk advisory and rewrite `compromised-db.json`.
- `bun run build` — bundle `src/scan.ts` → `dist/scan.js` (Node ESM, shebanged, chmod +x). Runs automatically on `npm publish` via `prepublishOnly`.

There is no separate lint step; `tsconfig.json` is strict (`noUncheckedIndexedAccess`, `noImplicitOverride`) and `noEmit` — type-checking happens through the editor / `tsc --noEmit` if needed.

`bunfig.toml` pins `minimumReleaseAge = 86400` (24h) as supply-chain hardening. Do not lower this without a stated reason.

Maintain `CHANGELOG.md` for user-visible changes. Add unreleased entries as changes land, and move them under a dated version heading when cutting an npm release.

## Architecture

A zero-runtime-dependency CLI that detects known-compromised npm package versions in lockfiles. Two halves:

**Database build (offline, `scripts/update-compromised-db.ts`)**
The Snyk advisory page is a Nuxt SPA — only 30 of ~172 rows render server-side, and `?page=N` is ignored. The script fetches the advisory HTML, enumerates every preloaded `/_nuxt/*.js` chunk, and locates the chunk that contains the full dataset embedded as `JSON.parse('[...]')`. It then normalizes Snyk's `{=1.2.3,=1.2.4}` version-set syntax into a sorted `versions[]` array and writes `compromised-db.json`. If Snyk changes the page shape, the extractor in `extractSnykRowsFromChunk` is the place to fix.

**Scanner (`src/scanner.ts`)**
`scanLockFiles(root, db)` builds a `name → version → {snykId, snykUrl}` index from the DB, walks the tree skipping `node_modules` and dot-dirs, and dispatches per lockfile type. Each parser is intentionally dependency-free and tolerant of multiple format versions:

- **npm** (`package-lock.json`, `npm-shrinkwrap.json`): handles lockfileVersion 1 (`dependencies` tree), 2 (both), and 3 (`packages` only). For v2/v3, the real package name is the substring after the final `node_modules/` segment, or `info.name` for aliases/workspace links.
- **bun** (`bun.lock`): parsed as JSONC (strips line/block comments and trailing commas); each entry's value is `["name@version", ...]`. `bun.lockb` (binary) throws with a clear remediation message — not supported.
- **pnpm** (`pnpm-lock.yaml`): parsed line-by-line (no YAML lib). Header regex handles v5 (`/foo/1.2.3`), v6 (`/foo@1.2.3`), and v9 (`foo@1.2.3`, may be quoted), plus scoped names and peer-dep `(peer@x)` suffixes.
- **yarn** (`yarn.lock`): block-structured, supports both classic v1 (`version "x"`) and berry v2+ (`version: x`). Names come from the comma-separated descriptors in the header, splitting on the last `@`.

Per-file parse errors are captured in `result.errors` and do not abort the overall scan. `src/scan.ts` is the thin CLI wrapper that exits 1 on any finding, 0 otherwise.

## Adding a new lockfile format

1. Add the filename to `LOCK_FILENAMES` in `src/scanner.ts`.
2. Write `scan<Format>LockFile(file, index)` returning `Finding[]` and add it to the dispatch in `scanLockFiles`.
3. Extend the `Ecosystem` union in `src/types.ts`.
4. Add a fixture under `tests/fixtures/` and assert it scans cleanly against the current DB.
