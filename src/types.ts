export type CompromisedPackage = {
  name: string;
  ecosystem: "npm";
  versions: string[];
  snykId: string;
  snykUrl: string;
};

export type CompromisedDb = {
  source: string;
  incident: string;
  fetchedAt: string;
  totalPackages: number;
  packages: CompromisedPackage[];
};

export type Ecosystem = "npm" | "bun" | "pnpm" | "yarn";

export type Finding = {
  lockfile: string;
  ecosystem: Ecosystem;
  package: string;
  version: string;
  snykId: string;
  snykUrl: string;
};

export type ScanError = { file: string; error: string };

export type ScanResult = {
  scannedFiles: string[];
  findings: Finding[];
  errors: ScanError[];
};

/** package name → version → snyk identifiers */
export type CompromisedIndex = Map<
  string,
  Map<string, { snykId: string; snykUrl: string }>
>;
