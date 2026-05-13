/**
 * Bundles src/scan.ts into a single dist/scan.js executable that runs under
 * plain node (so `npx mini-shai-hulud-scanner` works without bun installed).
 */
import { chmod, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const outfile = resolve(root, "dist/scan.js");

const result = await Bun.build({
  entrypoints: [resolve(root, "src/scan.ts")],
  outdir: resolve(root, "dist"),
  target: "node",
  format: "esm",
  minify: false,
});

if (!result.success) {
  for (const log of result.logs) console.error(log);
  process.exit(1);
}

const bundled = await Bun.file(outfile).text();
await writeFile(outfile, `#!/usr/bin/env node\n${bundled}`);
await chmod(outfile, 0o755);
console.log(`built ${outfile}`);
