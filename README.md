# mini-shai-hulud-scanner

A tiny, zero-dependency CLI that scans your project's lockfiles for npm packages compromised in the **TanStack "mini Shai-Hulud" npm supply-chain incident (May 2026)** — the follow-up to the original Shai-Hulud worm. The list of affected `package@version` pairs is sourced from the official [Snyk advisory](https://security.snyk.io/TanStack-npm-Supply-Chain-Compromise-May-2026) and bundled with the tool.

It works on `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (classic + berry), and `bun.lock`.

## Why

If `npm install` ever resolved one of the malicious tarballs onto your machine — even transitively, even briefly — that version is pinned in your lockfile. Reading the lockfile is the cheapest, most reliable way to know whether you were exposed. This scanner does exactly that and nothing else: no network calls at scan time, no telemetry, no install-time scripts to audit.

## Install / run

The fastest way is `npx` — no install, always uses the bundled DB shipped with the latest release:

```sh
npx mini-shai-hulud-scanner            # scan the current directory
npx mini-shai-hulud-scanner ./path     # scan a specific directory
```

Or install globally:

```sh
npm i -g mini-shai-hulud-scanner
mini-shai-hulud-scanner
```

The scanner recursively walks the target directory, **skipping `node_modules/` and dot-directories** (`.git`, `.next`, etc.), and inspects every supported lockfile it finds. Monorepos with multiple lockfiles are fine — each is scanned independently.

## Reading the output

Clean run:

```
root: /Users/you/code/your-app
db:   /.../compromised-db.json (172 compromised packages)
scanned 1 lock file(s):
  - pnpm-lock.yaml

no compromised packages found
```

Exit code: **`0`** — no compromised versions present.

Hit:

```
1 compromised package(s) found:

  @tanstack/query-core@5.59.20  [pnpm]  SNYK-JS-TANSTACKQUERYCORE-XXXXXXX
    in apps/web/pnpm-lock.yaml
    https://security.snyk.io/vuln/SNYK-JS-TANSTACKQUERYCORE-XXXXXXX
```

Exit code: **`1`** — at least one compromised version found. The non-zero exit makes the scanner CI-friendly:

```yaml
# .github/workflows/scan.yml
- run: npx mini-shai-hulud-scanner
```

If a lockfile fails to parse, it's reported in an `errors:` block and the rest of the scan still completes — one bad file won't hide findings in the others.

## What "compromised" means here

A finding means the **exact resolved version** in your lockfile matches a version flagged by the Snyk advisory. Semver ranges in `package.json` are not consulted — only what was actually installed. If you see a finding:

1. Check the Snyk URL printed for the affected package — it lists the malicious behavior and the safe versions.
2. Bump to a known-good version, delete the lockfile entry (or regenerate the lockfile), and reinstall.
3. Rotate any secrets that may have been exposed on the machine where `npm install` ran while the bad version was on disk — the Shai-Hulud family of malware harvests tokens.

## Format-specific notes

- **`bun.lockb`** (binary lockfile) is not parsed. The scanner throws with instructions to regenerate a text lockfile (`bun install --save-text-lockfile`) so the contents are inspectable.
- **pnpm** lockfiles are parsed line-by-line and handle v5/v6/v9 key shapes, including scoped packages and peer-dep `(peer@x)` suffixes.
- **yarn** parsing covers both classic v1 (`version "x"`) and berry v2+ (`version: x`).
- **npm** parsing covers lockfileVersion 1, 2, and 3, including workspace links and aliased dependencies (`info.name`).

## Updating the compromised database

The DB is a snapshot committed to the repo at `compromised-db.json`. It's refreshed by re-scraping the Snyk advisory:

```sh
bun run update-db
```

The scraper handles the fact that Snyk's page is a Nuxt SPA — only 30 of ~172 rows render server-side, so it instead pulls the dataset out of the inlined `JSON.parse('[...]')` payload in the page's JS chunks. If Snyk restructures the page and the scraper breaks, the fix lives in `scripts/update-compromised-db.ts`.

You can also point the scanner at a custom DB file:

```sh
npx mini-shai-hulud-scanner . ./my-compromised-db.json
```

The DB shape is documented in `src/types.ts` (`CompromisedDb`).

## Development

Bun is the dev runtime; the published `dist/scan.js` runs under plain Node ≥18.

```sh
bun test              # run the test suite
bun run scan ./fixture-dir
bun run build         # bundle src/scan.ts -> dist/scan.js
```

`bunfig.toml` pins `minimumReleaseAge = 86400` so `bun install` refuses any dependency version younger than 24 hours — a small piece of supply-chain hygiene aimed at exactly the class of attack this tool detects.

## Limitations

- Scope is intentionally narrow: lockfile-only, npm ecosystem only, one named incident's package list. It is **not** a general SCA tool (use `npm audit`, Snyk, OSV-Scanner, etc. for that).
- A clean scan means none of the *resolved versions* in your lockfile match the advisory list. It does not prove the machine that produced the lockfile was never compromised.
- The bundled DB is a point-in-time snapshot. For long-lived branches, re-run with a fresh `npx` invocation (or `bun run update-db`) before relying on the result.

## License

See repository for license details.
