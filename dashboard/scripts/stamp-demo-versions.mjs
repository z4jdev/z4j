/**
 * Stamp only z4j release-version carriers in a copied demo-data tree.
 *
 * Version-like fields also describe Python, PostgreSQL, the wire protocol,
 * and user payloads. File-and-shape matching keeps those independent values
 * out of the release bump even when they happen to contain bare semver.
 */
import { constants } from "node:fs";
import { access, lstat, readFile, readdir, writeFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

// Match the stable and canonical PyPA prerelease forms used by package waves.
// Do not accept arbitrary suffixes or local build identifiers as release data.
const RELEASE_VERSION_SOURCE = String.raw`\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?`;
const RELEASE_VERSION = new RegExp(`^${RELEASE_VERSION_SOURCE}$`);

export function isReleaseVersion(version) {
  return (
    typeof version === "string" &&
    !/[\r\n]/.test(version) &&
    RELEASE_VERSION.test(version)
  );
}
const REQUIRED_SYSTEM_FILES = new Set([
  "system/health.json",
  "system/health-system.json",
  "system/schedulers.json",
]);

function isCarrierDocument(path) {
  return (
    REQUIRED_SYSTEM_FILES.has(path) ||
    /^projects\/[^/]+\/agents\.json$/.test(path)
  );
}

/**
 * Require the production demo-data source to be a real, readable directory.
 * The demo cannot be published without its exact release-carrier inventory.
 */
export async function requireDemoDataTree(root) {
  const rootPath = resolve(root);
  let metadata;
  try {
    metadata = await lstat(rootPath);
  } catch {
    throw new Error(`required demo-data tree is unavailable: ${rootPath}`);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(
      `required demo-data tree is not a real directory: ${rootPath}`,
    );
  }
  if ((metadata.mode & 0o555) === 0) {
    throw new Error(`required demo-data tree is not readable: ${rootPath}`);
  }
  try {
    await access(rootPath, constants.R_OK | constants.X_OK);
  } catch {
    throw new Error(`required demo-data tree is not readable: ${rootPath}`);
  }
  return rootPath;
}

function requireRecord(value, location) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${location} must be a JSON object`);
  }
  return value;
}

function inspectField(record, key, version, location) {
  const object = requireRecord(record, location);
  const current = object[key];
  if (!isReleaseVersion(current)) {
    throw new Error(`${location}.${key} must be a bare release number`);
  }
  return current !== version;
}

function inspectDocument(path, document, version) {
  if (path === "system/health.json") {
    return {
      key: "version",
      changes: [inspectField(document, "version", version, path)],
    };
  }
  if (path === "system/health-system.json") {
    return {
      key: "z4j_version",
      changes: [inspectField(document, "z4j_version", version, path)],
    };
  }
  if (path === "system/schedulers.json") {
    const root = requireRecord(document, path);
    if (!Array.isArray(root.schedulers) || root.schedulers.length === 0) {
      throw new Error(`${path}.schedulers must be a non-empty JSON array`);
    }
    return {
      key: "version",
      changes: root.schedulers.map((scheduler, index) => {
        const schedulerRecord = requireRecord(
          scheduler,
          `${path}.schedulers[${index}]`,
        );
        return inspectField(
          schedulerRecord.info,
          "version",
          version,
          `${path}.schedulers[${index}].info`,
        );
      }),
    };
  }
  if (/^projects\/[^/]+\/agents\.json$/.test(path)) {
    if (!Array.isArray(document) || document.length === 0) {
      throw new Error(`${path} must be a non-empty JSON array`);
    }
    return {
      key: "agent_version",
      changes: document.map((agent, index) =>
        inspectField(agent, "agent_version", version, `${path}[${index}]`),
      ),
    };
  }
  return null;
}

function relativeJsonPath(root, path) {
  const candidate = relative(root, path);
  if (
    candidate === "" ||
    candidate === ".." ||
    candidate.startsWith(`..${sep}`) ||
    isAbsolute(candidate)
  ) {
    throw new Error(`demo-data path escapes its root: ${path}`);
  }
  return candidate.split(sep).join("/");
}

function stampText(before, key, version, expectedFields) {
  if (!/^[a-z0-9_]+$/.test(key)) {
    throw new Error(`unsafe version-carrier key: ${key}`);
  }
  const keyPattern = new RegExp(`"${key}"\\s*:`, "g");
  const keyFields = before.match(keyPattern)?.length ?? 0;
  if (keyFields !== expectedFields) {
    throw new Error(
      `expected ${expectedFields} textual ${key} carrier(s), found ${keyFields}`,
    );
  }

  const pattern = new RegExp(
    `("${key}"\\s*:\\s*")${RELEASE_VERSION_SOURCE}(")`,
    "g",
  );
  let fields = 0;
  const after = before.replace(pattern, (_match, head, tail) => {
    fields += 1;
    return `${head}${version}${tail}`;
  });
  if (fields !== expectedFields) {
    throw new Error(
      `expected ${expectedFields} bare-semver ${key} carrier(s), found ${fields}`,
    );
  }
  return after;
}

export async function stampDemoVersions(root, version, expectedInventory) {
  if (!isReleaseVersion(version)) {
    throw new Error(`VERSION is not a release number: ${version}`);
  }

  const rootPath = resolve(root);
  const missingSystemFiles = new Set(REQUIRED_SYSTEM_FILES);
  let agentFiles = 0;
  let files = 0;
  let fields = 0;
  let changedFiles = 0;
  let changedFields = 0;
  const pendingWrites = [];

  const walk = async (dir) => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = resolve(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(path);
        continue;
      }
      if (!entry.isFile()) {
        throw new Error(`demo-data entry is not a regular file: ${path}`);
      }
      if (!entry.name.endsWith(".json")) continue;

      const relativePath = relativeJsonPath(rootPath, path);
      if (!isCarrierDocument(relativePath)) continue;
      const before = await readFile(path, "utf8");
      if (before.includes("\\")) {
        throw new Error(
          `${relativePath} contains a JSON escape; ` +
            "release-carrier documents must use literal keys and values",
        );
      }
      const document = JSON.parse(before);
      const inspection = inspectDocument(relativePath, document, version);
      if (inspection === null) {
        throw new Error(`unhandled release-carrier document: ${relativePath}`);
      }

      missingSystemFiles.delete(relativePath);
      if (/^projects\/[^/]+\/agents\.json$/.test(relativePath)) {
        agentFiles += 1;
      }
      files += 1;
      fields += inspection.changes.length;
      const changed = inspection.changes.filter(Boolean).length;
      const after = stampText(
        before,
        inspection.key,
        version,
        inspection.changes.length,
      );
      if ((after !== before) !== changed > 0) {
        throw new Error(
          `${relativePath} structural and textual version changes disagree`,
        );
      }
      const verification = inspectDocument(
        relativePath,
        JSON.parse(after),
        version,
      );
      if (
        verification === null ||
        verification.key !== inspection.key ||
        verification.changes.length !== inspection.changes.length ||
        verification.changes.some(Boolean)
      ) {
        throw new Error(`${relativePath} did not stamp every release carrier`);
      }
      if (after === before) continue;

      pendingWrites.push({ path, after, changed });
    }
  };

  await walk(rootPath);
  if (missingSystemFiles.size > 0) {
    throw new Error(
      `demo-data is missing required version carrier(s): ${[
        ...missingSystemFiles,
      ].join(", ")}`,
    );
  }
  if (agentFiles === 0) {
    throw new Error("demo-data has no project agent version carriers");
  }
  if (
    expectedInventory !== undefined &&
    (files !== expectedInventory.files || fields !== expectedInventory.fields)
  ) {
    throw new Error(
      `unexpected z4j version inventory: ${fields} field(s) in ` +
        `${files} file(s); expected ${expectedInventory.fields} field(s) ` +
        `in ${expectedInventory.files} file(s)`,
    );
  }

  for (const pending of pendingWrites) {
    await writeFile(pending.path, pending.after, "utf8");
    changedFiles += 1;
    changedFields += pending.changed;
  }

  return { files, fields, changedFiles, changedFields };
}
