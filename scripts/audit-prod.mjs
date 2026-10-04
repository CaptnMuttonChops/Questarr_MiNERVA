#!/usr/bin/env node
/* global console */
/* global process */
// Gate for `npm audit --omit=dev` that honours the project's VEX feed
// (security/vex/questarr.openvex.json). npm audit has no ignore list, so an advisory that
// has been assessed as `not_affected` (or `fixed`) would otherwise fail every build until
// upstream ships a patch. This script runs the audit, drops advisories covered by such a
// VEX statement, and fails if anything at or above --audit-level remains.
// Policy: docs/VULNERABILITY_MANAGEMENT.md §1.2–1.3, docs/VEX.md.
//
// Usage: node scripts/audit-prod.mjs [--audit-level=high] [--report=npm-audit-report.json]
//   --report reads an existing `npm audit --json` output instead of running the audit.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const SEVERITIES = ["info", "low", "moderate", "high", "critical"];
const SUPPRESSING_STATUSES = new Set(["not_affected", "fixed"]);
const VEX_PATH = "security/vex/questarr.openvex.json";

function parseArgs(argv) {
  const args = { auditLevel: "high", report: null };
  for (const arg of argv) {
    const [key, value] = arg.split("=");
    if (key === "--audit-level" && value) args.auditLevel = value;
    else if (key === "--report" && value) args.report = value;
    else {
      console.error(`Unknown argument: ${arg}`);
      process.exit(2);
    }
  }
  if (!SEVERITIES.includes(args.auditLevel)) {
    console.error(`Invalid --audit-level "${args.auditLevel}" (expected ${SEVERITIES.join("|")})`);
    process.exit(2);
  }
  return args;
}

function readAuditReport(reportPath) {
  if (reportPath) return JSON.parse(readFileSync(reportPath, "utf8"));
  try {
    return JSON.parse(execFileSync("npm", ["audit", "--omit=dev", "--json"], { encoding: "utf8" }));
  } catch (error) {
    // npm audit exits non-zero whenever it finds anything; the JSON is still on stdout.
    if (error.stdout) return JSON.parse(error.stdout);
    throw error;
  }
}

// Maps each advisory ID covered by a not_affected/fixed statement to the npm products
// (name + optional version) that statement covers, so a suppression never outlives the
// exact package version it was assessed against.
function suppressionsByAdvisory() {
  const vex = JSON.parse(readFileSync(VEX_PATH, "utf8"));
  const byId = new Map();
  for (const statement of vex.statements ?? []) {
    if (!SUPPRESSING_STATUSES.has(statement.status)) continue;
    const products = (statement.products ?? []).map((p) => parseNpmPurl(p["@id"])).filter(Boolean);
    const vuln = statement.vulnerability ?? {};
    for (const id of [vuln.name, ...(vuln.aliases ?? [])]) {
      if (!id) continue;
      const key = id.toUpperCase();
      byId.set(key, [...(byId.get(key) ?? []), ...products]);
    }
  }
  return byId;
}

// pkg:npm/%40scope/name@1.2.3 -> { name: "@scope/name", version: "1.2.3" }; version is null
// when the purl omits it (statement covers every version).
function parseNpmPurl(purl) {
  const match = /^pkg:npm\/([^@?#]+(?:\/[^@?#]+)?)(?:@([^?#]+))?/.exec(purl ?? "");
  if (!match) return null;
  return {
    name: decodeURIComponent(match[1]),
    version: match[2] ? decodeURIComponent(match[2]) : null,
  };
}

// Installed versions of a vulnerable package, from the lockfile paths npm audit reports.
function installedVersions(vuln) {
  const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
  return [
    ...new Set((vuln.nodes ?? []).map((node) => lock.packages?.[node]?.version).filter(Boolean)),
  ];
}

function isCovered(products, pkgName, versions) {
  if (!products || versions.length === 0) return false;
  return versions.every((version) =>
    products.some((p) => p.name === pkgName && (p.version === null || p.version === version))
  );
}

function advisoryId(via) {
  const match = /GHSA(-[0-9a-z]{4}){3}/i.exec(via.url ?? "");
  return match ? match[0].toUpperCase() : String(via.source);
}

const { auditLevel, report: reportPath } = parseArgs(process.argv.slice(2));
const report = readAuditReport(reportPath);
if (report.error) {
  console.error(`npm audit failed: ${report.error.summary ?? JSON.stringify(report.error)}`);
  process.exit(1);
}

const suppressions = suppressionsByAdvisory();
const threshold = SEVERITIES.indexOf(auditLevel);

// Root advisories are the object entries in each vulnerability's `via`; string entries just
// point at another vulnerable package in the chain, which is listed separately. An advisory
// is ignored only for a package whose every installed version a VEX statement covers.
const blocking = [];
const ignored = [];
for (const [pkgName, vuln] of Object.entries(report.vulnerabilities ?? {})) {
  const versions = installedVersions(vuln);
  const seen = new Set();
  for (const via of vuln.via ?? []) {
    if (typeof via !== "object") continue;
    const id = advisoryId(via);
    if (seen.has(id) || SEVERITIES.indexOf(via.severity) < threshold) continue;
    seen.add(id);
    const advisory = { ...via, id, pkgName, versions };
    (isCovered(suppressions.get(id), pkgName, versions) ? ignored : blocking).push(advisory);
  }
}

const describe = (a) =>
  `  - ${a.id} (${a.severity}) in ${a.pkgName}@${a.versions.join(", ") || "?"}: ${a.title ?? a.url}`;
if (ignored.length > 0) {
  console.log(`Ignored ${ignored.length} advisory(ies) assessed in ${VEX_PATH}:`);
  ignored.forEach((a) => console.log(describe(a)));
}
if (blocking.length > 0) {
  console.error(
    `Found ${blocking.length} ${auditLevel}+ advisory(ies) not covered by the VEX feed:`
  );
  blocking.forEach((a) => console.error(describe(a)));
  console.error(
    `Fix them (upgrade or overrides), or record a not_affected statement in ${VEX_PATH} (docs/VEX.md).`
  );
  process.exit(1);
}
console.log(`No ${auditLevel}+ advisories in production dependencies outside the VEX feed.`);
