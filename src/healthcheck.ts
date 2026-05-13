/**
 * Pre-scan supply-chain hygiene checks for the project itself. These run
 * against the scan root and are reported above the actual scan output. They
 * are advisory: failures do not change the exit code, they just hint at ways
 * the user could harden their own install pipeline before the next attack.
 */
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";

export type CheckResult = {
  passed: boolean;
  title: string;
  /** Multi-line explanation rendered dim below the title when the check fails (or when a passing check has an important caveat). */
  detail?: string;
};

async function readTextOrNull(p: string): Promise<string | null> {
  try {
    return await readFile(p, "utf8");
  } catch {
    return null;
  }
}

async function exists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * Pre-scan checks look at the **scan root** only — not at lockfiles discovered
 * recursively. The configuration we are advising on (bunfig.toml, .npmrc,
 * package.json pins) lives next to the project's primary lockfile; lockfiles
 * deep in subtrees (test fixtures, vendored dependencies, monorepo workspaces)
 * have their own configuration story and we shouldn't second-guess it from
 * the top.
 */
export async function runHealthChecks(root: string): Promise<CheckResult[]> {
  const [usesNpm, usesBun, usesPnpm, usesYarn] = await Promise.all([
    Promise.all([
      exists(join(root, "package-lock.json")),
      exists(join(root, "npm-shrinkwrap.json")),
    ]).then((xs) => xs.some(Boolean)),
    Promise.all([
      exists(join(root, "bun.lock")),
      exists(join(root, "bun.lockb")),
    ]).then((xs) => xs.some(Boolean)),
    exists(join(root, "pnpm-lock.yaml")),
    exists(join(root, "yarn.lock")),
  ]);

  return [
    checkPackageManager({ usesNpm, usesBun, usesPnpm, usesYarn }),
    ...(await checkReleaseAge(root, { usesBun, usesPnpm })),
    await checkPinnedDependencies(root),
  ];
}

function checkPackageManager(d: {
  usesNpm: boolean;
  usesBun: boolean;
  usesPnpm: boolean;
  usesYarn: boolean;
}): CheckResult {
  const hardened = [d.usesBun && "bun", d.usesPnpm && "pnpm"].filter(
    Boolean,
  ) as string[];
  if (hardened.length > 0) {
    return {
      passed: true,
      title: `Using a release-age-aware package manager (${hardened.join(", ")})`,
    };
  }
  if (d.usesNpm || d.usesYarn) {
    const pm = d.usesNpm ? "npm" : "yarn";
    return {
      passed: false,
      title: `Using ${pm}, which has no built-in release-age gate`,
      detail:
        `Switch to bun or pnpm so you can refuse package versions younger than 24h. ` +
        `Most malicious supply-chain releases are yanked within hours, so a small ` +
        `delay catches them before they reach your machine. npm and yarn have no ` +
        `equivalent setting.`,
    };
  }
  return {
    passed: false,
    title: "No recognized lockfile in scan root",
    detail:
      "Could not determine which package manager you use, so the release-age gate check was skipped.",
  };
}

async function checkReleaseAge(
  root: string,
  d: { usesBun: boolean; usesPnpm: boolean },
): Promise<CheckResult[]> {
  const out: CheckResult[] = [];
  const MIN_BUN_SECONDS = 86_400; // 24h
  const MIN_PNPM_MINUTES = 1_440; // 24h

  if (d.usesBun) {
    const bunfig = await readTextOrNull(join(root, "bunfig.toml"));
    const m = bunfig?.match(/^\s*minimumReleaseAge\s*=\s*(\d+)/m);
    const seconds = m ? Number(m[1]) : 0;
    if (seconds >= MIN_BUN_SECONDS) {
      out.push({
        passed: true,
        title: `bunfig.toml: minimumReleaseAge = ${seconds}s (≥ 24h)`,
      });
    } else {
      out.push({
        passed: false,
        title:
          seconds > 0
            ? `bunfig.toml: minimumReleaseAge = ${seconds}s (< 24h)`
            : "bunfig.toml: minimumReleaseAge not set",
        detail:
          "Add the following to bunfig.toml under [install]:\n" +
          "  minimumReleaseAge = 86400\n" +
          "Bun will refuse to install any package version published in the last 24h.",
      });
    }
  }
  if (d.usesPnpm) {
    const npmrc = await readTextOrNull(join(root, ".npmrc"));
    const m = npmrc?.match(/^\s*minimum-release-age\s*=\s*(\d+)/m);
    const minutes = m ? Number(m[1]) : 0;
    if (minutes >= MIN_PNPM_MINUTES) {
      out.push({
        passed: true,
        title: `.npmrc: minimum-release-age = ${minutes}m (≥ 24h)`,
      });
    } else {
      out.push({
        passed: false,
        title:
          minutes > 0
            ? `.npmrc: minimum-release-age = ${minutes}m (< 24h)`
            : ".npmrc: minimum-release-age not set",
        detail:
          "Add the following to .npmrc:\n" +
          "  minimum-release-age=1440\n" +
          "pnpm 10+ will refuse to install any package version published in the last 24h.",
      });
    }
  }
  return out;
}

async function checkPinnedDependencies(root: string): Promise<CheckResult> {
  const text = await readTextOrNull(join(root, "package.json"));
  if (!text) {
    return {
      passed: false,
      title: "No package.json in scan root — pinning check skipped",
    };
  }
  let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    pkg = JSON.parse(text);
  } catch {
    return {
      passed: false,
      title: "package.json could not be parsed — pinning check skipped",
    };
  }
  const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
  const entries = Object.entries(deps);
  if (entries.length === 0) {
    return {
      passed: true,
      title: "No runtime dependencies declared",
    };
  }

  // A "floating" range is anything except an exact semver, a git/file/workspace
  // spec, or a URL. The conservative heuristic: anything starting with ^ ~ > <
  // = * or containing || (range alternatives).
  const floating = entries.filter(([, v]) => /^[\^~><=*]|\|\|/.test(v.trim()));

  if (floating.length === 0) {
    return {
      passed: true,
      title: `Dependencies pinned to exact versions (${entries.length} dep${entries.length === 1 ? "" : "s"})`,
      detail:
        "Note: pinning is a hardening measure, not a permanent state. Refresh pins manually on a cadence you control — and review what each refresh pulls in. The trade-off is more maintenance for fewer silent supply-chain entries.",
    };
  }

  const preview = floating
    .slice(0, 3)
    .map(([k, v]) => `${k}@${v}`)
    .join(", ");
  return {
    passed: false,
    title: `${floating.length} dependency(ies) use floating ranges in package.json`,
    detail:
      `Pin every dependency to an exact version so a fresh install can't silently pick up a compromised patch release. ` +
      `This is a temporary hardening measure — you'll need to refresh manually, but for supply-chain-sensitive projects the trade-off is worth it. ` +
      `Floating: ${preview}${floating.length > 3 ? `, …(+${floating.length - 3} more)` : ""}`,
  };
}
