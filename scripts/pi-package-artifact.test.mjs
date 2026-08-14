import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { resolve } from "node:path";

const packageDirectory = resolve("packages/pi-approval-guardian");

function packManifest() {
  const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
    cwd: packageDirectory,
    encoding: "utf8",
  });
  const parsed = JSON.parse(output);
  return Array.isArray(parsed) ? parsed[0] : Object.values(parsed)[0];
}

test("the public Pi artifact contains exactly its publication allowlist", () => {
  const manifest = packManifest();
  const paths = manifest.files.map(({ path }) => path).sort();
  assert.deepEqual(paths, [
    "LICENSE",
    "LICENSES/Apache-2.0.txt",
    "NOTICE",
    "README.es.md",
    "README.ja.md",
    "README.ko.md",
    "README.md",
    "README.zh-CN.md",
    "README.zh-TW.md",
    "docs/PUBLISHING.md",
    "docs/REFERENCE.md",
    "docs/UPSTREAM-GUARDIAN-RESEARCH.md",
    "extensions/index.ts",
    "package.json",
    "src/authorization-provenance.ts",
    "src/config.ts",
    "src/directory-scan-cache.ts",
    "src/gate.ts",
    "src/guardian-status.ts",
    "src/normalized-decision.ts",
    "src/path-rules.ts",
    "src/policy.ts",
    "src/review-presentation.ts",
    "src/review.ts",
    "src/reviewer-channels.ts",
    "src/reviewer-session.ts",
    "src/reviewer-tools.ts",
    "src/shared-decision.ts",
    "src/shell-private-data.ts",
    "src/tool-actions.ts",
    "src/tool-input-lock.ts",
  ]);
});
