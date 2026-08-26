#!/usr/bin/env node
/*
 * Closed dashboard data-image generator.
 *
 * Docker invokes this file only after dashboard_authority.py has validated the
 * reviewed policy and supplied its SHA-256 as a build argument.  Acquisition
 * and build are separate Docker RUN instructions: only internal-acquire may
 * use the network; internal-build is executed with BuildKit --network=none.
 * No URL, package, command, or tool seal is accepted from argv or ambient
 * workflow input.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  constants,
  chmodSync,
  chownSync,
  copyFileSync,
  cpSync,
  existsSync,
  fchmodSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
  closeSync,
  fsyncSync,
} from "node:fs";
import { basename, dirname, join, relative, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";

const POLICY_PATH = "/authority/dashboard-authority-policy.json";
const SOURCE_ROOT = "/source/dashboard";
const ACQUIRED_ROOT = "/acquired";
const OUTPUT_ROOT = "/out";
const PAYLOAD_ROOT = "/out/payload";
const RUN_EVIDENCE_ROOT = "/out/run-evidence";
const WORKSPACE_ROOT = "/tmp/z4j-dashboard-workspace";
const INSTALL_STORE_ROOT = "/tmp/z4j-dashboard-install-store";
const BUILD_PNPM_PATH = "/tmp/z4j-dashboard-workspace/.tools/pnpm.cjs";
const BUILD_UID = 65532;
const BUILD_GID = 65532;
const MAX_BYTES = 512 * 1024 * 1024;
const PLATFORMS = new Set(["linux/amd64", "linux/arm64"]);
const BUILD_IDS = new Set(["A", "B"]);
const HEX64 = /^[0-9a-f]{64}$/u;
const POSITIVE = Number.isSafeInteger;

function fail(message) {
  throw new Error(`dashboard-generator: ${message}`);
}

function sha256(raw) {
  return createHash("sha256").update(raw).digest("hex");
}

function asciiJsonString(value) {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/gu, (character) => {
    const code = character.charCodeAt(0);
    return `\\u${code.toString(16).padStart(4, "0")}`;
  });
}

function canonicalJson(value, terminalLf = true) {
  function normalize(item, context) {
    if (item === null || typeof item === "boolean" || typeof item === "string") {
      return item;
    }
    if (typeof item === "number") {
      if (!Number.isSafeInteger(item)) fail(`${context} contains a non-integral number`);
      return item;
    }
    if (Array.isArray(item)) {
      return item.map((child, index) => normalize(child, `${context}[${index}]`));
    }
    if (typeof item === "object") {
      const result = {};
      for (const key of Object.keys(item).sort()) {
        result[key] = normalize(item[key], `${context}.${key}`);
      }
      return result;
    }
    fail(`${context} contains an unsupported JSON value`);
  }
  const raw = Buffer.from(asciiJsonString(normalize(value, "JSON")), "ascii");
  return terminalLf ? Buffer.concat([raw, Buffer.from("\n")]) : raw;
}

function tarField(header, start, length, context) {
  const field = header.subarray(start, start + length);
  const nul = field.indexOf(0);
  const content = field.subarray(0, nul < 0 ? field.length : nul);
  if ([...content].some((byte) => byte < 0x20 || byte > 0x7e)) {
    fail(`${context} contains a non-ASCII tar field`);
  }
  return content.toString("ascii");
}

function tarOctal(header, start, length, context) {
  const value = tarField(header, start, length, context).trim();
  if (!/^[0-7]+$/u.test(value)) fail(`${context} contains a non-octal tar field`);
  const parsed = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(parsed) || parsed < 0) fail(`${context} tar integer is out of range`);
  return parsed;
}

function tarMembers(raw, context) {
  let expanded;
  try {
    if (raw.at(0) !== 0x1f || raw.at(1) !== 0x8b) fail(`${context} is not gzip framed`);
    expanded = gunzipSync(raw, { maxOutputLength: MAX_BYTES });
  } catch (error) {
    fail(`${context} cannot be boundedly decompressed: ${error.message}`);
  }
  const result = [];
  const seen = new Map();
  let total = 0;
  let offset = 0;
  let terminalBlocks = 0;
  while (offset + 512 <= expanded.length) {
    const header = expanded.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      terminalBlocks += 1;
      offset += 512;
      if (terminalBlocks === 2) break;
      continue;
    }
    if (terminalBlocks !== 0) fail(`${context} contains a split terminal marker`);
    const expectedChecksum = tarOctal(header, 148, 8, context);
    const checksumHeader = Buffer.from(header);
    checksumHeader.fill(0x20, 148, 156);
    const actualChecksum = checksumHeader.reduce((sum, byte) => sum + byte, 0);
    if (actualChecksum !== expectedChecksum) fail(`${context} tar checksum differs`);
    const name = tarField(header, 0, 100, context);
    const prefix = tarField(header, 345, 155, context);
    const rawPath = `${prefix ? `${prefix}/` : ""}${name}`;
    const combined = rawPath.replace(/\/$/u, "");
    const parts = combined.split("/");
    if (
      combined.length === 0 ||
      rawPath.startsWith("./") ||
      rawPath.includes("//") ||
      combined.startsWith("/") ||
      combined.includes("\\") ||
      combined.includes("\0") ||
      combined.includes("\n") ||
      parts.includes("..") ||
      parts.includes("")
    ) {
      fail(`${context} contains an unsafe tar path`);
    }
    const typeByte = header.at(156);
    const type = typeByte === 0 || typeByte === 0x30 ? "file" : typeByte === 0x35 ? "directory" : null;
    if (type === null) fail(`${context} contains a link, special, GNU-longname, or PAX member`);
    const size = tarOctal(header, 124, 12, context);
    if ((type === "directory" && size !== 0) || size > MAX_BYTES) {
      fail(`${context} member size differs`);
    }
    const mode = tarOctal(header, 100, 8, context);
    if ((mode & 0o7000) !== 0) fail(`${context} contains privileged mode bits`);
    if (seen.has(combined)) fail(`${context} contains a duplicate tar path`);
    for (let index = 1; index < parts.length; index += 1) {
      if (seen.get(parts.slice(0, index).join("/")) === "file") {
        fail(`${context} contains a file/directory collision`);
      }
    }
    if (type === "file" && [...seen.keys()].some((path) => path.startsWith(`${combined}/`))) {
      fail(`${context} contains a file/directory collision`);
    }
    seen.set(combined, type);
    total += size;
    if (total > MAX_BYTES || result.length >= 500000) fail(`${context} expansion exceeds bounds`);
    const record = { mode: mode.toString(8).padStart(4, "0"), path: combined, size, type };
    Object.defineProperty(record, "payload", {
      enumerable: false,
      value: expanded.subarray(offset + 512, offset + 512 + size),
    });
    result.push(record);
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  if (terminalBlocks !== 2 || expanded.subarray(offset).some((byte) => byte !== 0)) {
    fail(`${context} terminal framing differs`);
  }
  if (result.length === 0) fail(`${context} has no members`);
  return result;
}

function verifyTarAuthority(raw, authority, context) {
  const records = tarMembers(raw, context);
  const framing = canonicalJson({ files: records, format: "z4j-production-tar-members-v1" }, false);
  if (
    !HEX64.test(authority.members_sha256 ?? "") ||
    sha256(framing) !== authority.members_sha256 ||
    records.length !== authority.members_entries ||
    records.reduce((total, item) => total + item.size, 0) !== authority.members_bytes
  ) {
    fail(`${context} semantic member authority differs`);
  }
  return records;
}

function extractReviewedTar(raw, authority, destination, context, selected = null) {
  const members = verifyTarAuthority(raw, authority, context);
  ownerPrivateNew(destination);
  const selectedSet = selected === null ? null : new Set(selected);
  const chosen = members.filter(
    (member) => selectedSet === null || selectedSet.has(member.path),
  );
  const directories = new Set();
  for (const member of chosen) {
    const parts = member.path.split("/");
    const stop = member.type === "directory" ? parts.length : parts.length - 1;
    for (let index = 1; index <= stop; index += 1) {
      directories.add(parts.slice(0, index).join("/"));
    }
  }
  for (const logical of [...directories].sort((left, right) => {
    const depth = left.split("/").length - right.split("/").length;
    return depth === 0 ? Buffer.compare(Buffer.from(left), Buffer.from(right)) : depth;
  })) {
    const target = join(destination, ...logical.split("/"));
    if (existsSync(target)) continue;
    mkdirSync(target, { mode: 0o700, recursive: false });
  }
  for (const member of chosen) {
    const target = join(destination, ...member.path.split("/"));
    if (member.type === "directory") continue;
    atomicWrite(target, member.payload, 0o600);
  }
  if (selectedSet !== null) {
    const extracted = new Set(records(destination, new Set()).map((item) => item.path));
    if (
      extracted.size !== selectedSet.size ||
      [...selectedSet].some((path) => !extracted.has(path))
    ) {
      fail(`${context} selected extraction set differs`);
    }
  }
  return members;
}

function exactObject(value, keys, context) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${context} is not an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${context} keys differ`);
  }
  return value;
}

function regular(path, maximum = MAX_BYTES) {
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    fail(`${path} cannot be opened directly: ${error.message}`);
  }
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 0n || before.size > BigInt(maximum)) {
      fail(`${path} is not one bounded regular inode`);
    }
    const raw = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    for (const key of ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]) {
      if (before[key] !== after[key]) fail(`${path} changed while reading`);
    }
    if (BigInt(raw.length) !== before.size) fail(`${path} size changed while reading`);
    return raw;
  } finally {
    closeSync(descriptor);
  }
}

function loadPolicy() {
  const raw = regular(POLICY_PATH, 4 * 1024 * 1024);
  if (raw.at(-1) !== 10 || raw.includes(13) || raw.includes(0)) fail("policy framing differs");
  let value;
  try {
    value = JSON.parse(raw.toString("ascii"));
  } catch (error) {
    fail(`policy is not JSON: ${error.message}`);
  }
  if (!canonicalJson(value).equals(raw)) fail("policy is not canonical ASCII JSON plus LF");
  if (!HEX64.test(process.env.Z4J_POLICY_SHA256 ?? "")) fail("policy SHA input differs");
  if (sha256(raw) !== process.env.Z4J_POLICY_SHA256) fail("policy SHA does not match bytes");
  if (!PLATFORMS.has(process.env.Z4J_PLATFORM)) fail("platform differs");
  if (!BUILD_IDS.has(process.env.Z4J_BUILD_ID)) fail("build identity differs");
  return value;
}

function requireReady(policy) {
  const dashboard = exactObject(
    policy.dashboard,
    new Set([
      "advisory_receipt_format",
      "build_receipt_format",
      "bundle_tree_format",
      "generator",
      "index_descriptor_order",
      "inventory_format",
      "layer_count_per_platform",
      "node",
      "payload_root",
      "platforms",
      "pnpm",
      "sbom_format",
      "source_date_epoch",
      "source_projection",
      "store_inventory_format",
      "store_tree_format",
      "tree_format",
    ]),
    "dashboard policy",
  );
  const generator = exactObject(
    dashboard.generator,
    new Set([
      "build_context",
      "builder",
      "commands",
      "docker",
      "dockerfile",
      "execution_plane",
      "tools",
      "trivy",
    ]),
    "dashboard generator",
  );
  if (generator.builder !== "z4j-production-dashboard") fail("builder identity differs");
  const buildContext = exactObject(
    generator.build_context,
    new Set(["format", "source_files"]),
    "dashboard build context",
  );
  if (buildContext.format !== "z4j-production-dashboard-build-context-v1") {
    fail("dashboard build-context format differs");
  }
  const buildSourceFiles = exactObject(
    buildContext.source_files,
    new Set([
      "docker/production/dashboard_authority.py",
      "docker/production/generators/dashboard.mjs",
      "docker/production/production_authority_common.py",
      "docker/production/production_material_build.py",
    ]),
    "dashboard build-context source files",
  );
  for (const [path, seal] of Object.entries(buildSourceFiles)) {
    exactObject(seal, new Set(["sha256", "size"]), `dashboard build source ${path}`);
    if (!HEX64.test(seal.sha256 ?? "") || !POSITIVE(seal.size) || seal.size <= 0) {
      fail(`dashboard build source ${path} is unsealed`);
    }
    const internal = join("/authority", basename(path));
    verifySeal(regular(internal), seal, `dashboard build source ${path}`);
  }
  const dockerPlatforms = exactObject(
    exactObject(generator.docker, new Set(["platforms"]), "Docker authority").platforms,
    new Set(["linux/amd64", "linux/arm64"]),
    "Docker platform authority",
  );
  for (const [platform, docker] of Object.entries(dockerPlatforms)) {
    exactObject(
      docker,
      new Set(["path", "sha256", "size", "version_output_sha256"]),
      `Docker ${platform}`,
    );
    if (
      docker.path !== "/usr/bin/docker" ||
      !HEX64.test(docker.sha256 ?? "") ||
      !POSITIVE(docker.size) ||
      !HEX64.test(docker.version_output_sha256 ?? "")
    ) {
      fail(`outer Docker ${platform} authority is unready`);
    }
  }
  const dockerfile = exactObject(
    generator.dockerfile,
    new Set(["path", "sha256", "size"]),
    "generator Dockerfile",
  );
  if (
    dockerfile.path !== "docker/production/generators/dashboard.Dockerfile" ||
    !HEX64.test(dockerfile.sha256 ?? "") ||
    !POSITIVE(dockerfile.size)
  ) {
    fail("generator Dockerfile authority is unready");
  }
  const commands = exactObject(generator.commands, new Set(["build", "install"]), "commands");
  const expectedInstall = [
    "node",
    BUILD_PNPM_PATH,
    "install",
    "--offline",
    "--frozen-lockfile",
    "--store-dir",
    INSTALL_STORE_ROOT,
    "--package-import-method=copy",
  ];
  const expectedBuild = [
    "node",
    BUILD_PNPM_PATH,
    "run",
    "build",
  ];
  if (JSON.stringify(commands.install) !== JSON.stringify(expectedInstall)) fail("install argv differs");
  if (JSON.stringify(commands.build) !== JSON.stringify(expectedBuild)) fail("build argv differs");
  if (!POSITIVE(dashboard.source_date_epoch) || dashboard.source_date_epoch <= 0) {
    fail("SOURCE_DATE_EPOCH is unselected");
  }
  const node = exactObject(
    dashboard.node,
    new Set(["image", "index_digest", "index_size", "platforms", "version"]),
    "Node authority",
  );
  if (!POSITIVE(node.index_size) || node.index_size <= 0) fail("Node index is unsealed");
  const nodePlatforms = exactObject(
    node.platforms,
    new Set(["linux/amd64", "linux/arm64"]),
    "Node platform matrix",
  );
  for (const platform of ["linux/amd64", "linux/arm64"]) {
    const descriptor = exactObject(
      nodePlatforms[platform],
      new Set(["config_digest", "config_size", "manifest_digest", "manifest_size"]),
      `Node ${platform}`,
    );
    if (
      !/^sha256:[0-9a-f]{64}$/u.test(descriptor.config_digest ?? "") ||
      !/^sha256:[0-9a-f]{64}$/u.test(descriptor.manifest_digest ?? "") ||
      !POSITIVE(descriptor.config_size) ||
      !POSITIVE(descriptor.manifest_size)
    ) {
      fail(`Node ${platform} descriptor is unsealed`);
    }
  }
  const projection = exactObject(
    dashboard.source_projection,
    new Set([
      "algorithm",
      "bytes",
      "entries",
      "exclusions",
      "executables",
      "inclusions",
      "record_framing",
      "sha256",
    ]),
    "dashboard source projection",
  );
  if (!HEX64.test(projection.sha256 ?? "") || !POSITIVE(projection.entries) || !POSITIVE(projection.bytes)) {
    fail("dashboard source projection is unsealed");
  }
  const sourceFiles = records(SOURCE_ROOT, new Set());
  if (
    sourceFiles.some(
      (item) =>
        item.mode !== "0644" ||
        item.path.endsWith(".map") ||
        item.path.endsWith(".pyc") ||
        item.path.endsWith(".pyo") ||
        item.path.split("/").includes("__pycache__") ||
        item.path.split("/").includes(".DS_Store"),
    )
  ) {
    fail("dashboard source copy contains an excluded path");
  }
  const projectionFiles = sourceFiles.map((item) => ({ ...item, path: `dashboard/${item.path}` }));
  const projectionRaw = canonicalJson(
    { files: projectionFiles, format: projection.algorithm },
    false,
  );
  if (
    sha256(projectionRaw) !== projection.sha256 ||
    projectionFiles.length !== projection.entries ||
    projectionFiles.reduce((total, item) => total + item.size, 0) !== projection.bytes
  ) {
    fail("dashboard source projection bytes differ");
  }
  const pnpm = exactObject(
    dashboard.pnpm,
    new Set([
      "archive_members_bytes",
      "archive_members_entries",
      "archive_members_sha256",
      "archive_sha256",
      "archive_size",
      "binary_sha256",
      "binary_size",
      "published_at_utc",
      "registry_packument",
      "registry_sha256",
      "registry_size",
      "release_receipt_format",
      "tarball",
      "version",
    ]),
    "pnpm authority",
  );
  for (const [digestKey, sizeKey] of [
    ["archive_sha256", "archive_size"],
    ["binary_sha256", "binary_size"],
    ["registry_sha256", "registry_size"],
  ]) {
    if (!HEX64.test(pnpm[digestKey] ?? "") || !POSITIVE(pnpm[sizeKey]) || pnpm[sizeKey] <= 0) {
      fail(`pnpm ${digestKey} seal is unready`);
    }
  }
  if (
    !HEX64.test(pnpm.archive_members_sha256 ?? "") ||
    !POSITIVE(pnpm.archive_members_entries) ||
    pnpm.archive_members_entries <= 0 ||
    !POSITIVE(pnpm.archive_members_bytes) ||
    pnpm.archive_members_bytes <= 0
  ) {
    fail("pnpm archive semantic member authority is unready");
  }
  if (typeof pnpm.published_at_utc !== "string" || !pnpm.published_at_utc.endsWith("Z")) {
    fail("pnpm publication time is unready");
  }
  const trivy = exactObject(
    generator.trivy,
    new Set(["database", "database_archive", "platforms", "version"]),
    "Trivy authority",
  );
  const trivyPlatforms = exactObject(
    trivy.platforms,
    new Set(["linux/amd64", "linux/arm64"]),
    "Trivy platform authority",
  );
  for (const [platform, native] of Object.entries(trivyPlatforms)) {
    exactObject(
      native,
      new Set(["archive", "binary", "version_output_sha256"]),
      `Trivy ${platform}`,
    );
    const item = native.archive;
    exactObject(
      item,
      new Set(["members_bytes", "members_entries", "members_sha256", "sha256", "size", "url"]),
      "Trivy payload",
    );
    if (!HEX64.test(item.sha256 ?? "") || !POSITIVE(item.size) || item.size <= 0) {
      fail("Trivy payload seal is unready");
    }
    if (
      !HEX64.test(item.members_sha256 ?? "") ||
      !POSITIVE(item.members_entries) ||
      item.members_entries <= 0 ||
      !POSITIVE(item.members_bytes) ||
      item.members_bytes <= 0
    ) {
      fail("Trivy semantic member authority is unready");
    }
    if (typeof item.url !== "string" || !item.url.startsWith("https://")) fail("Trivy URL differs");
    exactObject(native.binary, new Set(["sha256", "size"]), `Trivy binary ${platform}`);
    if (
      !HEX64.test(native.binary.sha256 ?? "") ||
      !POSITIVE(native.binary.size) ||
      native.binary.size <= 0 ||
      !HEX64.test(native.version_output_sha256 ?? "")
    ) {
      fail(`Trivy native authority ${platform} is unready`);
    }
  }
  const nativeTrivy = trivyPlatforms[process.env.Z4J_PLATFORM];
  const databaseArchive = trivy.database_archive;
  exactObject(
    databaseArchive,
    new Set(["members_bytes", "members_entries", "members_sha256", "sha256", "size", "url"]),
    "Trivy database archive",
  );
  if (
    !HEX64.test(databaseArchive.sha256 ?? "") ||
    !POSITIVE(databaseArchive.size) ||
    !HEX64.test(databaseArchive.members_sha256 ?? "") ||
    !POSITIVE(databaseArchive.members_entries) ||
    !POSITIVE(databaseArchive.members_bytes) ||
    typeof databaseArchive.url !== "string" ||
    !databaseArchive.url.startsWith("https://")
  ) {
    fail("Trivy database archive authority is unready");
  }
  exactObject(
    trivy.database,
    new Set([
      "downloaded_at_utc",
      "metadata_sha256",
      "name",
      "next_update_utc",
      "schema_version",
      "tree_sha256",
      "updated_at_utc",
    ]),
    "Trivy database",
  );
  if (
    trivy.version !== "0.74.0" ||
    trivy.database.name !== "trivy-db" ||
    trivy.database.schema_version !== 2 ||
    !HEX64.test(trivy.database.metadata_sha256 ?? "") ||
    !HEX64.test(trivy.database.tree_sha256 ?? "")
  ) {
    fail("Trivy database/scanner identity is unready");
  }
  const tools = exactObject(generator.tools, new Set(["tar"]), "dashboard tools");
  const tarPlatforms = exactObject(
    exactObject(tools.tar, new Set(["platforms"]), "tar authority").platforms,
    new Set(["linux/amd64", "linux/arm64"]),
    "tar platform authority",
  );
  for (const [platform, authority] of Object.entries(tarPlatforms)) {
    exactObject(
      authority,
      new Set(["path", "sha256", "size", "version_output_sha256"]),
      `tar ${platform}`,
    );
    if (
      authority.path !== "/bin/tar" ||
      !HEX64.test(authority.sha256 ?? "") ||
      !POSITIVE(authority.size) ||
      !HEX64.test(authority.version_output_sha256 ?? "")
    ) {
      fail(`tar tool authority ${platform} is unready`);
    }
  }
  return {
    dashboard,
    generator,
    pnpm,
    projection,
    tar: tarPlatforms[process.env.Z4J_PLATFORM],
    trivy: { ...trivy, ...nativeTrivy },
  };
}

function ownerPrivateNew(path) {
  if (existsSync(path)) fail(`${path} already exists`);
  mkdirSync(path, { mode: 0o700, recursive: false });
}

function atomicWrite(path, raw, mode = 0o600) {
  mkdirSync(dirname(path), { mode: 0o700, recursive: true });
  const descriptor = openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    mode,
  );
  try {
    writeFileSync(descriptor, raw);
    fsyncSync(descriptor);
    fchmodSync(descriptor, mode);
    const observed = fstatSync(descriptor);
    if (!observed.isFile() || observed.nlink !== 1 || observed.size !== raw.length) {
      fail(`${path} output identity differs`);
    }
  } finally {
    closeSync(descriptor);
  }
}

function verifySeal(raw, authority, context) {
  if (raw.length !== authority.size || sha256(raw) !== authority.sha256) fail(`${context} seal differs`);
}

async function fetchExact(authority, context) {
  const response = await fetch(authority.url, { redirect: "error" });
  if (response.status !== 200 || response.url !== authority.url) fail(`${context} HTTP identity differs`);
  if (response.headers.get("content-encoding") !== null) {
    fail(`${context} response uses an unreviewed content encoding`);
  }
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^[1-9][0-9]*$/u.test(declaredLength) || Number(declaredLength) !== authority.size)
  ) {
    fail(`${context} HTTP content length differs`);
  }
  if (response.body === null) fail(`${context} response body is absent`);
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > authority.size || size > MAX_BYTES) {
        await reader.cancel();
        fail(`${context} exceeds its exact bound`);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  const raw = Buffer.concat(chunks, size);
  verifySeal(raw, authority, context);
  return raw;
}

function runExact(argv, cwd, environment, identity = null) {
  if (!Array.isArray(argv) || argv.length === 0 || argv.some((item) => typeof item !== "string" || item.length === 0)) {
    fail("command argv differs");
  }
  const result = spawnSync(argv[0], argv.slice(1), {
    cwd,
    env: environment,
    encoding: null,
    maxBuffer: 32 * 1024 * 1024,
    shell: false,
    timeout: 21_600_000,
    ...(identity === null ? {} : { gid: identity.gid, uid: identity.uid }),
  });
  if (result.error) fail(`command could not run: ${result.error.message}`);
  if (result.status !== 0) fail(`command failed (${argv[0]} status ${result.status})`);
  return { stderr: Buffer.from(result.stderr ?? ""), stdout: Buffer.from(result.stdout ?? "") };
}

function verifyTool(path, authority, versionArgs) {
  const raw = regular(path);
  verifySeal(raw, authority, `${basename(path)} binary`);
  const transcript = runExact([path, ...versionArgs], "/authority", {
    LANG: "C.UTF-8",
    PATH: "/usr/bin:/bin",
    TZ: "UTC",
  });
  if (sha256(Buffer.concat([transcript.stdout, transcript.stderr])) !== authority.version_output_sha256) {
    fail(`${basename(path)} version transcript differs`);
  }
  verifySeal(regular(path), authority, `${basename(path)} binary after execution`);
}

function walkFiles(root) {
  const result = [];
  function visit(directory) {
    for (const name of readdirSync(directory).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))) {
      const path = join(directory, name);
      const status = lstatSync(path);
      if (status.isSymbolicLink()) fail(`tree contains symlink ${path}`);
      if (status.isDirectory()) visit(path);
      else if (status.isFile() && status.nlink === 1) result.push(path);
      else fail(`tree contains unsupported inode ${path}`);
    }
  }
  visit(root);
  return result;
}

function records(root, excluded = new Set(["inventory.json"])) {
  return walkFiles(root)
    .map((path) => {
      const logical = relative(root, path).split(sep).join("/");
      if (logical.startsWith("../") || logical === "") fail("tree escaped its root");
      const raw = regular(path);
      return { mode: (statSync(path).mode & 0o777).toString(8).padStart(4, "0"), path: logical, sha256: sha256(raw), size: raw.length };
    })
    .filter((item) => !excluded.has(item.path));
}

function installInventory(root, platform, dashboard) {
  const files = records(root);
  if (files.length === 0) fail("dashboard payload is empty");
  const inventoryRaw = canonicalJson({ files, format: dashboard.inventory_format, platform });
  atomicWrite(join(root, "inventory.json"), inventoryRaw, 0o644);
  const treeRaw = canonicalJson({ files, format: dashboard.tree_format, platform }, false);
  return {
    inventory_entries: files.length,
    inventory_sha256: sha256(inventoryRaw),
    inventory_size: inventoryRaw.length,
    tree_bytes: files.reduce((total, item) => total + item.size, 0),
    tree_sha256: sha256(treeRaw),
  };
}

function distTree(root, format) {
  const files = records(root, new Set()).map((item) => ({ ...item, path: `dist/${item.path}` }));
  if (files.length === 0) fail("dashboard dist is empty");
  return { bytes: files.reduce((total, item) => total + item.size, 0), files, format, sha256: sha256(canonicalJson({ files, format }, false)) };
}

function outputMarker(dist) {
  const lines = records(dist, new Set())
    .filter((item) => !new Set([".build-inputs.sha256", ".build-output.sha256"]).has(item.path))
    .map((item) => `${item.sha256}  ${item.path}\n`)
    .join("");
  return Buffer.from(`${sha256(Buffer.from(lines))}\n`, "ascii");
}

function pnpmLockComponents(raw) {
  const text = raw.toString("utf8");
  if (
    text.includes("\r") ||
    text.includes("\t") ||
    !text.startsWith("lockfileVersion: '9.0'\n") ||
    text.split("\nimporters:\n").length !== 2 ||
    text.split("\npackages:\n").length !== 2 ||
    text.split("\nsnapshots:\n").length !== 2 ||
    text.indexOf("\nimporters:\n") > text.indexOf("\npackages:\n") ||
    text.indexOf("\npackages:\n") > text.indexOf("\nsnapshots:\n")
  ) {
    fail("pnpm lock framing differs");
  }

  function scalar(rawValue, context) {
    let value = rawValue;
    if (value.startsWith("'") || value.endsWith("'")) {
      if (!(value.startsWith("'") && value.endsWith("'") && value.length >= 2)) {
        fail(`${context} quoting differs`);
      }
      value = value.slice(1, -1).replaceAll("''", "'");
    }
    if (!value || /[\u0000-\u001f\u007f]/u.test(value) || value.trim() !== value) {
      fail(`${context} scalar differs`);
    }
    return value;
  }

  function blocks(section, context, allowEmpty) {
    const lines = section.split("\n");
    const starts = [];
    for (let index = 0; index < lines.length; index += 1) {
      if (/^  \S.*:(?: \{\})?$/u.test(lines[index])) starts.push(index);
    }
    if (!allowEmpty && starts.length === 0) fail(`${context} is empty`);
    const result = [];
    for (let offset = 0; offset < starts.length; offset += 1) {
      const start = starts[offset];
      const stop = offset + 1 < starts.length ? starts[offset + 1] : lines.length;
      let header = lines[start].slice(2);
      const inlineEmpty = header.endsWith(": {}");
      header = header.slice(0, inlineEmpty ? -4 : -1);
      const body = lines.slice(start + 1, stop);
      if (inlineEmpty && body.some((line) => line !== "")) fail(`${context} inline-empty body differs`);
      result.push({ body, key: scalar(header, `${context} key`) });
    }
    const covered = new Set();
    for (const start of starts) {
      const stop = starts.find((value) => value > start) ?? lines.length;
      for (let index = start; index < stop; index += 1) covered.add(index);
    }
    for (let index = 0; index < lines.length; index += 1) {
      if (!covered.has(index) && lines[index] !== "") fail(`${context} top-level framing differs`);
    }
    return result;
  }

  const importerSection = text.split("\nimporters:\n", 2)[1].split("\npackages:\n", 1)[0];
  const importerBlocks = blocks(importerSection, "pnpm importer set", false);
  if (importerBlocks.length !== 1 || importerBlocks[0].key !== ".") {
    fail("pnpm importer set is not the exact root importer");
  }
  const rootTargets = new Map();
  const importerFields = new Map();
  let importerGroup = null;
  let importerDependency = null;
  for (const line of importerBlocks[0].body) {
    if (line === "") continue;
    const groupMatch = line.match(/^    (dependencies|devDependencies|optionalDependencies):$/u);
    if (groupMatch !== null) {
      importerGroup = groupMatch[1];
      importerDependency = null;
      continue;
    }
    const dependencyMatch = line.match(/^      (\S.*):$/u);
    if (dependencyMatch !== null && importerGroup !== null) {
      importerDependency = scalar(dependencyMatch[1], "pnpm importer dependency");
      const identity = `${importerGroup}\0${importerDependency}`;
      if (importerFields.has(identity)) fail("pnpm importer dependency is duplicate");
      importerFields.set(identity, new Set());
      continue;
    }
    const fieldMatch = line.match(/^        (specifier|version): (\S.*)$/u);
    if (fieldMatch !== null && importerGroup !== null && importerDependency !== null) {
      const fields = importerFields.get(`${importerGroup}\0${importerDependency}`);
      if (fields === undefined || fields.has(fieldMatch[1])) fail("pnpm importer field is duplicate");
      fields.add(fieldMatch[1]);
      if (fieldMatch[1] === "version") {
        const version = scalar(fieldMatch[2], `pnpm importer ${importerDependency} version`);
        const target = `${importerDependency}@${version}`;
        const roots = rootTargets.get(target) ?? [];
        if (roots.includes(importerGroup)) fail("pnpm importer target is duplicate");
        roots.push(importerGroup);
        rootTargets.set(target, roots);
      }
      continue;
    }
    fail("pnpm root importer framing differs");
  }
  if ([...importerFields.values()].some((fields) => fields.size !== 2 || !fields.has("specifier") || !fields.has("version"))) {
    fail("pnpm importer dependency fields differ");
  }
  if (rootTargets.size === 0) fail("pnpm root importer is empty");

  const packageSection = text.split("\npackages:\n", 2)[1].split("\nsnapshots:\n", 1)[0];
  const packageBlocks = blocks(packageSection, "pnpm package universe", false);
  const packages = new Map();
  for (const { body, key } of packageBlocks) {
    const separator = key.lastIndexOf("@");
    if (separator <= 0 || separator === key.length - 1 || key.includes("(")) {
      fail(`pnpm package identity differs: ${key}`);
    }
    const name = key.slice(0, separator);
    const version = key.slice(separator + 1);
    const matches = [];
    for (const line of body) {
      const match = line.trim().match(/(?:^|[,{])integrity: (sha512-[A-Za-z0-9+/=]+)(?:[,}]|$)/u);
      if (match !== null) matches.push(match[1]);
    }
    if (matches.length !== 1) fail(`pnpm integrity is absent or ambiguous: ${key}`);
    const decoded = Buffer.from(matches[0].slice("sha512-".length), "base64");
    if (decoded.length !== 64 || decoded.toString("base64") !== matches[0].slice("sha512-".length)) {
      fail(`pnpm integrity differs: ${key}`);
    }
    function constraint(field) {
      const matches = body
        .slice()
        .map((line) => line.trim().match(new RegExp(`^${field}: \\[([^\\]]*)\\]$`, "u")))
        .filter((match) => match !== null);
      if (matches.length > 1) fail(`pnpm ${field} constraint is ambiguous: ${key}`);
      if (matches.length === 0) return null;
      const values = matches[0][1].split(",").map((item) => item.trim());
      if (values.some((item) => !/^!?[a-z0-9_-]+$/u.test(item)) || new Set(values).size !== values.length) {
        fail(`pnpm ${field} constraint differs: ${key}`);
      }
      return values;
    }
    if (packages.has(key)) fail(`pnpm package is duplicate: ${key}`);
    packages.set(key, {
      cpu: constraint("cpu"),
      integrity_sha512: matches[0],
      libc: constraint("libc"),
      name,
      os: constraint("os"),
      version,
    });
  }

  const snapshotSection = text.split("\nsnapshots:\n", 2)[1];
  const snapshotBlocks = blocks(snapshotSection, "pnpm snapshot graph", false);
  const snapshots = new Map();
  function dependencyTarget(nameRaw, versionRaw, context) {
    const name = scalar(nameRaw, `${context} name`);
    const version = scalar(versionRaw, `${context} version`);
    if (version.startsWith("link:") || version.startsWith("file:") || version.startsWith("workspace:")) {
      fail(`${context} uses a non-registry target`);
    }
    return `${name}@${version}`;
  }
  for (const { body, key } of snapshotBlocks) {
    if (snapshots.has(key)) fail(`pnpm snapshot is duplicate: ${key}`);
    const packageKey = key.split("(", 1)[0];
    const metadata = packages.get(packageKey);
    if (metadata === undefined) fail(`pnpm snapshot has no package metadata: ${key}`);
    const edges = { dependencies: [], optionalDependencies: [] };
    const transitivePeers = [];
    let field = null;
    let optional = false;
    for (const line of body) {
      if (line === "") continue;
      const fieldMatch = line.match(/^    (dependencies|optionalDependencies|transitivePeerDependencies):$/u);
      if (fieldMatch !== null) {
        field = fieldMatch[1];
        continue;
      }
      if (line === "    optional: true") {
        if (optional) fail(`pnpm snapshot optional marker is duplicate: ${key}`);
        optional = true;
        field = null;
        continue;
      }
      const edgeMatch = line.match(/^      (\S.*): (\S.*)$/u);
      if (edgeMatch !== null && (field === "dependencies" || field === "optionalDependencies")) {
        edges[field].push(dependencyTarget(edgeMatch[1], edgeMatch[2], `pnpm snapshot ${key}`));
        continue;
      }
      const peerMatch = line.match(/^      - (\S.*)$/u);
      if (peerMatch !== null && field === "transitivePeerDependencies") {
        transitivePeers.push(scalar(peerMatch[1], `pnpm snapshot ${key} transitive peer`));
        continue;
      }
      fail(`pnpm snapshot framing differs: ${key}`);
    }
    for (const values of [...Object.values(edges), transitivePeers]) {
      if (values.length !== new Set(values).size) fail(`pnpm snapshot edge is duplicate: ${key}`);
      values.sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
    }
    snapshots.set(key, {
      ...metadata,
      dependencies: edges.dependencies,
      key,
      optional,
      optional_dependencies: edges.optionalDependencies,
      package_key: packageKey,
      root_groups: [...(rootTargets.get(key) ?? [])].sort(),
      transitive_peer_dependencies: transitivePeers,
    });
  }
  const representedPackages = new Set([...snapshots.values()].map((item) => item.package_key));
  if ([...packages.keys()].some((key) => !representedPackages.has(key))) {
    fail("pnpm package universe has no exact snapshot instance");
  }
  for (const target of rootTargets.keys()) {
    if (!snapshots.has(target)) fail(`pnpm importer target is dangling: ${target}`);
  }
  for (const component of snapshots.values()) {
    for (const target of [...component.dependencies, ...component.optional_dependencies]) {
      if (!snapshots.has(target)) fail(`pnpm snapshot edge is dangling: ${target}`);
    }
  }
  const components = [...snapshots.values()];
  components.sort((left, right) => {
    return Buffer.compare(Buffer.from(left.key), Buffer.from(right.key));
  });
  return components;
}

function platformLockComponents(components, platform) {
  if (!PLATFORMS.has(platform)) fail("pnpm native realization platform differs");
  const cpu = platform === "linux/amd64" ? "x64" : "arm64";
  function permits(values, target) {
    if (values === null) return true;
    const positives = values.filter((value) => !value.startsWith("!"));
    if (values.includes(`!${target}`)) return false;
    return positives.length === 0 || positives.includes(target);
  }
  const byKey = new Map(components.map((component) => [component.key, component]));
  if (byKey.size !== components.length) fail("pnpm snapshot graph contains duplicate instances");
  const roots = components
    .filter((component) => component.root_groups.length > 0)
    .map((component) => ({
      optional: component.root_groups.every((group) => group === "optionalDependencies"),
      target: component.key,
    }));
  if (roots.length === 0) fail("pnpm native realization has no root importer targets");
  const selectedKeys = new Set();
  const queue = roots;
  while (queue.length > 0) {
    const edge = queue.shift();
    const component = byKey.get(edge.target);
    if (component === undefined) fail(`pnpm native realization edge is dangling: ${edge.target}`);
    const compatible =
      permits(component.os, "linux") &&
      permits(component.cpu, cpu) &&
      permits(component.libc, "glibc");
    if (!compatible) {
      if (edge.optional || component.optional) continue;
      fail(`pnpm required snapshot is incompatible with ${platform}: ${component.key}`);
    }
    if (selectedKeys.has(component.key)) continue;
    selectedKeys.add(component.key);
    for (const target of component.dependencies) queue.push({ optional: false, target });
    for (const target of component.optional_dependencies) queue.push({ optional: true, target });
  }
  const selected = components.filter((component) => selectedKeys.has(component.key));
  if (selected.length === 0) fail("pnpm native realization is empty");
  return selected;
}

function installedComponents(workspace, expectedComponents) {
  const virtualStore = join(workspace, "node_modules/.pnpm");
  if (!existsSync(virtualStore) || lstatSync(virtualStore).isSymbolicLink()) {
    fail("pnpm native virtual store is absent or indirect");
  }
  const result = [];
  for (const instance of readdirSync(virtualStore).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)))) {
    const instanceRoot = join(virtualStore, instance);
    const instanceStatus = lstatSync(instanceRoot);
    if (instance === "lock.yaml" && instanceStatus.isFile()) continue;
    if (instance === "node_modules" && instanceStatus.isDirectory() && !instanceStatus.isSymbolicLink()) continue;
    if (!instanceStatus.isDirectory() || instanceStatus.isSymbolicLink()) {
      fail("pnpm virtual store contains an unknown root entry");
    }
    const modules = join(instanceRoot, "node_modules");
    if (!existsSync(modules) || lstatSync(modules).isSymbolicLink() || !lstatSync(modules).isDirectory()) {
      fail(`pnpm virtual-store instance has no direct node_modules root: ${instance}`);
    }
    const candidates = [];
    for (const name of readdirSync(modules)) {
      const candidate = join(modules, name);
      const status = lstatSync(candidate);
      if (status.isSymbolicLink()) continue;
      if (!status.isDirectory()) fail(`pnpm virtual-store instance contains a non-directory: ${instance}`);
      if (name.startsWith("@")) {
        for (const child of readdirSync(candidate)) {
          const scoped = join(candidate, child);
          const childStatus = lstatSync(scoped);
          if (childStatus.isSymbolicLink()) continue;
          if (!childStatus.isDirectory()) fail(`pnpm scoped virtual-store entry differs: ${instance}`);
          if (existsSync(join(scoped, "package.json"))) candidates.push(join(scoped, "package.json"));
        }
      } else if (existsSync(join(candidate, "package.json"))) {
        candidates.push(join(candidate, "package.json"));
      }
    }
    if (candidates.length !== 1) fail(`pnpm virtual-store instance root manifest is ambiguous: ${instance}`);
    const value = JSON.parse(regular(candidates[0], 4 * 1024 * 1024).toString("utf8"));
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      typeof value.name !== "string" ||
      typeof value.version !== "string" ||
      !value.name ||
      !value.version
    ) {
      fail("installed pnpm package identity differs");
    }
    result.push({ instance, name: value.name, version: value.version });
  }
  result.sort((left, right) => Buffer.compare(
    Buffer.from(`${left.name}\0${left.version}\0${left.instance}`),
    Buffer.from(`${right.name}\0${right.version}\0${right.instance}`),
  ));
  if (result.length === 0 || new Set(result.map((item) => item.instance)).size !== result.length) {
    fail("installed pnpm realization is empty or duplicate");
  }
  const expectedByIdentity = new Map();
  for (const component of expectedComponents) {
    const identity = `${component.name}\0${component.version}`;
    const values = expectedByIdentity.get(identity) ?? [];
    values.push(component.key);
    expectedByIdentity.set(identity, values);
  }
  const installedByIdentity = new Map();
  for (const item of result) {
    const identity = `${item.name}\0${item.version}`;
    const values = installedByIdentity.get(identity) ?? [];
    values.push(item);
    installedByIdentity.set(identity, values);
  }
  if (!canonicalJson(
    [...expectedByIdentity].map(([key, values]) => [key, values.length]).sort(),
    false,
  ).equals(canonicalJson(
    [...installedByIdentity].map(([key, values]) => [key, values.length]).sort(),
    false,
  ))) {
    fail("installed pnpm native realization differs from the reachable snapshot graph");
  }
  const realized = [];
  for (const identity of [...expectedByIdentity.keys()].sort()) {
    const expected = expectedByIdentity.get(identity).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
    const observed = installedByIdentity.get(identity).sort((left, right) => Buffer.compare(Buffer.from(left.instance), Buffer.from(right.instance)));
    for (let index = 0; index < expected.length; index += 1) {
      realized.push({ ...observed[index], snapshot_key: expected[index] });
    }
  }
  realized.sort((left, right) => Buffer.compare(
    Buffer.from(`${left.name}\0${left.version}\0${left.snapshot_key}\0${left.instance}`),
    Buffer.from(`${right.name}\0${right.version}\0${right.snapshot_key}\0${right.instance}`),
  ));
  return realized;
}

function pnpmPurl(name, version) {
  return `pkg:npm/${name.split("/").map(encodeURIComponent).join("/")}@${encodeURIComponent(version)}`;
}

function trivyProperty(properties, name, context) {
  if (!Array.isArray(properties)) fail(`${context} properties differ`);
  const values = [];
  for (const [index, item] of properties.entries()) {
    exactObject(item, new Set(["name", "value"]), `${context} property ${index}`);
    if (item.name === name) values.push(item.value);
  }
  if (values.length !== 1 || typeof values[0] !== "string" || !values[0]) {
    fail(`${context} property ${name} differs`);
  }
  return values[0];
}

function expectedTrivyPackages(lockUniverse) {
  const expected = new Map();
  for (const item of lockUniverse) {
    if (expected.has(item.key)) fail("pnpm lock contains a duplicate snapshot identity");
    expected.set(item.key, [item.name, item.version]);
  }
  return expected;
}

function trivyPnpmInventory(report, expected) {
  exactObject(
    report,
    new Set(["ArtifactName", "ArtifactType", "CreatedAt", "ReportID", "Results", "SchemaVersion", "Trivy"]),
    "raw Trivy advisory report",
  );
  if (
    report.SchemaVersion !== 2 ||
    !["ArtifactName", "ArtifactType", "CreatedAt", "ReportID", "Trivy"].every(
      (key) => typeof report[key] === "string" && report[key],
    ) ||
    !Array.isArray(report.Results) ||
    report.Results.length !== 1
  ) {
    fail("raw Trivy advisory envelope differs");
  }
  const result = exactObject(
    report.Results[0],
    new Set(["Class", "Packages", "Target", "Type"]),
    "raw Trivy pnpm result",
  );
  if (
    result.Class !== "lang-pkgs" ||
    result.Type !== "pnpm" ||
    result.Target !== "pnpm-lock.yaml" ||
    !Array.isArray(result.Packages) ||
    result.Packages.length === 0
  ) {
    fail("raw Trivy pnpm result identity differs");
  }
  const required = new Set(["AnalyzedBy", "ID", "Identifier", "Name", "Relationship", "Version"]);
  const allowed = new Set([...required, "DependsOn", "Dev", "Indirect"]);
  const actual = new Map();
  for (const [position, item] of result.Packages.entries()) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      fail(`raw Trivy package ${position} differs`);
    }
    const keys = Object.keys(item);
    if ([...required].some((key) => !keys.includes(key)) || keys.some((key) => !allowed.has(key))) {
      fail(`raw Trivy package ${position} fields differ`);
    }
    const identifier = exactObject(item.Identifier, new Set(["PURL", "UID"]), `raw Trivy package ${position} ID`);
    const identity = expected.get(item.ID);
    const purl = typeof item.Name === "string" && typeof item.Version === "string"
      ? pnpmPurl(item.Name, item.Version)
      : "";
    if (
      !identity ||
      identity[0] !== item.Name ||
      identity[1] !== item.Version ||
      identifier.PURL !== purl ||
      typeof identifier.UID !== "string" ||
      !/^[0-9a-f]{16}$/u.test(identifier.UID) ||
      item.AnalyzedBy !== "pnpm" ||
      !["direct", "indirect"].includes(item.Relationship) ||
      actual.has(item.ID) ||
      ["Dev", "Indirect"].some((key) => key in item && typeof item[key] !== "boolean") ||
      !Array.isArray(item.DependsOn ?? []) ||
      (item.DependsOn ?? []).some((child) => typeof child !== "string" || !child) ||
      new Set(item.DependsOn ?? []).size !== (item.DependsOn ?? []).length
    ) {
      fail("raw Trivy package identity differs from pnpm-lock.yaml");
    }
    actual.set(item.ID, { id: item.ID, name: item.Name, purl, version: item.Version });
  }
  if (actual.size !== expected.size || [...expected.keys()].some((key) => !actual.has(key))) {
    fail("raw Trivy package inventory differs from pnpm-lock.yaml");
  }
  return [...actual.keys()].sort().map((key) => actual.get(key));
}

function trivyCycloneDxComponents(value, expected) {
  exactObject(
    value,
    new Set(["$schema", "bomFormat", "components", "dependencies", "metadata", "serialNumber", "specVersion", "version", "vulnerabilities"]),
    "raw Trivy CycloneDX",
  );
  if (
    value.$schema !== "http://cyclonedx.org/schema/bom-1.7.schema.json" ||
    value.bomFormat !== "CycloneDX" ||
    value.specVersion !== "1.7" ||
    value.version !== 1 ||
    typeof value.serialNumber !== "string" ||
    !value.serialNumber.startsWith("urn:uuid:") ||
    !Array.isArray(value.dependencies) ||
    !Array.isArray(value.vulnerabilities) ||
    value.vulnerabilities.length !== 0 ||
    !Array.isArray(value.components) ||
    value.components.length !== expected.size + 1
  ) {
    fail("raw Trivy CycloneDX envelope differs");
  }
  const metadata = exactObject(value.metadata, new Set(["component", "timestamp", "tools"]), "raw Trivy metadata");
  if (
    typeof metadata.timestamp !== "string" ||
    !metadata.timestamp ||
    !Array.isArray(metadata.tools) ||
    metadata.tools.length === 0 ||
    metadata.component === null ||
    typeof metadata.component !== "object" ||
    metadata.component.type !== "application"
  ) {
    fail("raw Trivy metadata differs");
  }
  const actual = new Map();
  const normalized = new Map();
  const references = new Set();
  let applicationCount = 0;
  for (const [position, component] of value.components.entries()) {
    if (component === null || typeof component !== "object" || Array.isArray(component)) {
      fail(`raw Trivy component ${position} differs`);
    }
    if (typeof component["bom-ref"] !== "string" || !component["bom-ref"] || references.has(component["bom-ref"])) {
      fail("raw Trivy component reference differs or is duplicate");
    }
    references.add(component["bom-ref"]);
    if (component.type === "application") {
      exactObject(component, new Set(["bom-ref", "name", "properties", "type"]), "raw Trivy application component");
      if (
        component.name !== "pnpm-lock.yaml" ||
        !Array.isArray(component.properties) ||
        component.properties.length !== 2 ||
        trivyProperty(component.properties, "aquasecurity:trivy:Class", "raw Trivy application") !== "lang-pkgs" ||
        trivyProperty(component.properties, "aquasecurity:trivy:Type", "raw Trivy application") !== "pnpm"
      ) {
        fail("raw Trivy application component differs");
      }
      applicationCount += 1;
      continue;
    }
    const keys = new Set(["bom-ref", "name", "properties", "purl", "type", "version"]);
    if ("group" in component) keys.add("group");
    exactObject(component, keys, `raw Trivy library ${position}`);
    const name = "group" in component ? `${component.group}/${component.name}` : component.name;
    const id = trivyProperty(component.properties, "aquasecurity:trivy:PkgID", `raw Trivy library ${position}`);
    const type = trivyProperty(component.properties, "aquasecurity:trivy:PkgType", `raw Trivy library ${position}`);
    const identity = expected.get(id);
    const purl = typeof name === "string" && typeof component.version === "string"
      ? pnpmPurl(name, component.version)
      : "";
    if (
      component.type !== "library" ||
      !Array.isArray(component.properties) ||
      component.properties.length !== 2 ||
      typeof component.name !== "string" ||
      !component.name ||
      ("group" in component && (typeof component.group !== "string" || !component.group.startsWith("@"))) ||
      !identity ||
      identity[0] !== name ||
      identity[1] !== component.version ||
      component.purl !== purl ||
      type !== "pnpm" ||
      actual.has(id)
    ) {
      fail("raw Trivy CycloneDX identity differs from pnpm-lock.yaml");
    }
    actual.set(id, { id, name, purl, version: component.version });
    const normalizedComponent = {
      "bom-ref": `urn:z4j:pnpm:${sha256(Buffer.from(id, "utf8"))}`,
      name: component.name,
      properties: [
        { name: "aquasecurity:trivy:PkgID", value: id },
        { name: "aquasecurity:trivy:PkgType", value: "pnpm" },
      ],
      purl,
      type: "library",
      version: component.version,
    };
    if ("group" in component) normalizedComponent.group = component.group;
    normalized.set(id, normalizedComponent);
  }
  if (
    applicationCount !== 1 ||
    actual.size !== expected.size ||
    [...expected.keys()].some((key) => !actual.has(key))
  ) {
    fail("raw Trivy CycloneDX inventory differs from pnpm-lock.yaml");
  }
  const ordered = [...actual.keys()].sort();
  return {
    components: ordered.map((key) => normalized.get(key)),
    packages: ordered.map((key) => actual.get(key)),
  };
}

function copyDirectTree(source, destination) {
  if (lstatSync(source).isSymbolicLink()) fail("source tree is indirect");
  cpSync(source, destination, {
    dereference: false,
    errorOnExist: true,
    force: false,
    preserveTimestamps: false,
    recursive: true,
    verbatimSymlinks: true,
  });
  walkFiles(destination);
}

function chownPrivateTree(root, uid, gid) {
  const paths = walkFiles(root);
  const directories = [];
  function visit(directory) {
    directories.push(directory);
    for (const name of readdirSync(directory)) {
      const path = join(directory, name);
      const status = lstatSync(path);
      if (status.isSymbolicLink()) fail("build workspace contains a symlink");
      if (status.isDirectory()) visit(path);
    }
  }
  visit(root);
  for (const path of paths) chownSync(path, uid, gid);
  for (const path of directories.reverse()) {
    chownSync(path, uid, gid);
    chmodSync(path, 0o700);
  }
}

function protectedTreeProjection(root, context, expectedUid = 0, requirePrivateMode = true) {
  function validate(directory) {
    const status = lstatSync(directory);
    if (
      !status.isDirectory() ||
      status.isSymbolicLink() ||
      status.uid !== expectedUid ||
      (requirePrivateMode && (status.mode & 0o022) !== 0)
    ) {
      fail(`${context} directory custody differs`);
    }
    for (const name of readdirSync(directory)) {
      const path = join(directory, name);
      const child = lstatSync(path);
      if (child.isDirectory()) validate(path);
      else if (
        !child.isFile() ||
        child.isSymbolicLink() ||
        child.uid !== expectedUid ||
        (requirePrivateMode && (child.mode & 0o022) !== 0)
      ) {
        fail(`${context} file custody differs`);
      }
    }
  }
  validate(root);
  return records(root, new Set());
}

function requireSameProjection(
  root,
  expected,
  context,
  expectedUid = 0,
  requirePrivateMode = true,
) {
  const actual = protectedTreeProjection(root, context, expectedUid, requirePrivateMode);
  if (!canonicalJson(actual, false).equals(canonicalJson(expected, false))) {
    fail(`${context} changed during unprivileged build execution`);
  }
}

async function acquire(policy) {
  const { dashboard, pnpm, trivy, tar } = requireReady(policy);
  ownerPrivateNew(ACQUIRED_ROOT);
  const tarRaw = regular(tar.path);
  verifySeal(tarRaw, tar, "tar binary");
  const capturedTar = join(ACQUIRED_ROOT, "bin/tar");
  atomicWrite(capturedTar, tarRaw, 0o555);
  verifyTool(capturedTar, tar, ["--version"]);
  const registryAuthority = { sha256: pnpm.registry_sha256, size: pnpm.registry_size, url: pnpm.registry_packument };
  const archiveAuthority = { sha256: pnpm.archive_sha256, size: pnpm.archive_size, url: pnpm.tarball };
  const registry = await fetchExact(registryAuthority, "pnpm registry response");
  const archive = await fetchExact(archiveAuthority, "pnpm archive");
  const pnpmMembers = verifyTarAuthority(
    archive,
    {
      members_bytes: pnpm.archive_members_bytes,
      members_entries: pnpm.archive_members_entries,
      members_sha256: pnpm.archive_members_sha256,
    },
    "pnpm archive",
  );
  if (
    pnpmMembers.filter((item) => item.path === "package/bin/pnpm.cjs" && item.type === "file").length !== 1
  ) {
    fail("pnpm archive has no unique reviewed binary member");
  }
  atomicWrite(join(ACQUIRED_ROOT, "evidence/pnpm-registry.json"), registry);
  atomicWrite(join(ACQUIRED_ROOT, "evidence/pnpm-archive.tgz"), archive);
  const unpack = "/tmp/z4j-pnpm-unpack";
  if (existsSync(unpack)) fail("pnpm unpack path already exists");
  try {
    extractReviewedTar(
      archive,
      {
        members_bytes: pnpm.archive_members_bytes,
        members_entries: pnpm.archive_members_entries,
        members_sha256: pnpm.archive_members_sha256,
      },
      unpack,
      "pnpm archive",
      ["package/bin/pnpm.cjs"],
    );
    const binary = regular(join(unpack, "package/bin/pnpm.cjs"));
    verifySeal(binary, { sha256: pnpm.binary_sha256, size: pnpm.binary_size }, "pnpm binary");
    atomicWrite(join(ACQUIRED_ROOT, "bin/pnpm.cjs"), binary, 0o644);
  } finally {
    rmSync(unpack, { force: true, recursive: true });
  }
  const release = {
    archive_members_bytes: pnpm.archive_members_bytes,
    archive_members_entries: pnpm.archive_members_entries,
    archive_members_sha256: pnpm.archive_members_sha256,
    archive_sha256: pnpm.archive_sha256,
    archive_size: pnpm.archive_size,
    binary_sha256: pnpm.binary_sha256,
    binary_size: pnpm.binary_size,
    filename: "pnpm-11.22.0.tgz",
    format: dashboard.pnpm.release_receipt_format,
    published_at_utc: dashboard.pnpm.published_at_utc,
    registry_response: { path: "evidence/pnpm-registry.json", sha256: pnpm.registry_sha256, size: pnpm.registry_size },
    url: pnpm.tarball,
    version: pnpm.version,
  };
  atomicWrite(join(ACQUIRED_ROOT, "evidence/pnpm-release.json"), canonicalJson(release));
  copyFileSync(join(SOURCE_ROOT, "pnpm-lock.yaml"), join(ACQUIRED_ROOT, "evidence/pnpm-lock.yaml"));
  mkdirSync(join(ACQUIRED_ROOT, "store"), { mode: 0o700 });
  const fetchRun = runExact(
    ["node", join(ACQUIRED_ROOT, "bin/pnpm.cjs"), "fetch", "--frozen-lockfile", "--store-dir", join(ACQUIRED_ROOT, "store")],
    SOURCE_ROOT,
    { CI: "true", LANG: "C.UTF-8", PATH: "/usr/local/bin:/usr/bin:/bin", TZ: "UTC" },
  );
  atomicWrite(join(ACQUIRED_ROOT, ".generator/run-evidence/pnpm-fetch.stdout"), fetchRun.stdout);
  atomicWrite(join(ACQUIRED_ROOT, ".generator/run-evidence/pnpm-fetch.stderr"), fetchRun.stderr);
  atomicWrite(
    join(ACQUIRED_ROOT, ".generator/run-evidence/pnpm-fetch.json"),
    canonicalJson({
      argv: ["node", join(ACQUIRED_ROOT, "bin/pnpm.cjs"), "fetch", "--frozen-lockfile", "--store-dir", join(ACQUIRED_ROOT, "store")],
      cwd: SOURCE_ROOT,
      environment: { CI: "true", LANG: "C.UTF-8", PATH: "/usr/local/bin:/usr/bin:/bin", TZ: "UTC" },
      exit_code: 0,
      format: "z4j-production-dashboard-pnpm-fetch-run-evidence-v1",
      stderr: { path: "pnpm-fetch.stderr", sha256: sha256(fetchRun.stderr), size: fetchRun.stderr.length },
      stdout: { path: "pnpm-fetch.stdout", sha256: sha256(fetchRun.stdout), size: fetchRun.stdout.length },
    }),
  );
  const trivyArchive = await fetchExact(trivy.archive, "Trivy archive");
  const trivyDatabase = await fetchExact(trivy.database_archive, "Trivy database");
  const trivyMembers = verifyTarAuthority(trivyArchive, trivy.archive, "Trivy archive");
  if (trivyMembers.filter((item) => item.path === "trivy" && item.type === "file").length !== 1) {
    fail("Trivy archive has no unique root binary");
  }
  const databaseMembers = verifyTarAuthority(
    trivyDatabase,
    trivy.database_archive,
    "Trivy database archive",
  );
  if (databaseMembers.some((item) => item.path !== "db" && !item.path.startsWith("db/"))) {
    fail("Trivy database archive escapes its exact db root");
  }
  atomicWrite(join(ACQUIRED_ROOT, "evidence/trivy-archive.tgz"), trivyArchive);
  atomicWrite(join(ACQUIRED_ROOT, "evidence/trivy-database.tar.gz"), trivyDatabase);
  atomicWrite(
    join(ACQUIRED_ROOT, "acquisition.json"),
    canonicalJson({
      build_id: process.env.Z4J_BUILD_ID,
      format: "z4j-production-dashboard-acquisition-v1",
      platform: process.env.Z4J_PLATFORM,
      policy_sha256: process.env.Z4J_POLICY_SHA256,
      records: records(ACQUIRED_ROOT),
    }),
  );
}

async function build(policy) {
  const { dashboard, generator, pnpm, projection, trivy } = requireReady(policy);
  if (!existsSync(ACQUIRED_ROOT) || lstatSync(ACQUIRED_ROOT).isSymbolicLink()) fail("acquisition is absent");
  const acquisition = regular(join(ACQUIRED_ROOT, "acquisition.json"));
  const acquisitionValue = JSON.parse(acquisition.toString("ascii"));
  exactObject(
    acquisitionValue,
    new Set(["build_id", "format", "platform", "policy_sha256", "records"]),
    "dashboard acquisition receipt",
  );
  if (!canonicalJson(acquisitionValue).equals(acquisition)) fail("acquisition receipt is noncanonical");
  if (
    acquisitionValue.format !== "z4j-production-dashboard-acquisition-v1" ||
    acquisitionValue.platform !== process.env.Z4J_PLATFORM ||
    acquisitionValue.build_id !== process.env.Z4J_BUILD_ID ||
    acquisitionValue.policy_sha256 !== process.env.Z4J_POLICY_SHA256 ||
    !canonicalJson(records(ACQUIRED_ROOT, new Set(["acquisition.json"])), false).equals(
      canonicalJson(acquisitionValue.records, false),
    )
  ) {
    fail("acquisition context or complete payload inventory differs");
  }
  const protectedAuthority = protectedTreeProjection("/authority", "dashboard authority");
  const protectedSource = protectedTreeProjection(SOURCE_ROOT, "dashboard source");
  const protectedAcquisition = protectedTreeProjection(ACQUIRED_ROOT, "dashboard acquisition");
  ownerPrivateNew(OUTPUT_ROOT);
  ownerPrivateNew(PAYLOAD_ROOT);
  ownerPrivateNew(RUN_EVIDENCE_ROOT);
  copyDirectTree(
    join(ACQUIRED_ROOT, ".generator/run-evidence"),
    join(RUN_EVIDENCE_ROOT, "acquisition"),
  );
  const evidence = join(PAYLOAD_ROOT, "evidence");
  mkdirSync(evidence, { mode: 0o700 });
  for (const name of ["pnpm-archive.tgz", "pnpm-lock.yaml", "pnpm-registry.json", "pnpm-release.json"]) {
    copyFileSync(join(ACQUIRED_ROOT, `evidence/${name}`), join(evidence, name));
  }
  mkdirSync(join(PAYLOAD_ROOT, "bin"), { mode: 0o700 });
  copyFileSync(join(ACQUIRED_ROOT, "bin/pnpm.cjs"), join(PAYLOAD_ROOT, "bin/pnpm.cjs"));
  copyDirectTree(join(ACQUIRED_ROOT, "store"), join(PAYLOAD_ROOT, "store"));
  const retainedStore = records(join(PAYLOAD_ROOT, "store"), new Set());
  if (existsSync(WORKSPACE_ROOT) || existsSync(INSTALL_STORE_ROOT)) fail("workspace/store already exists");
  copyDirectTree(SOURCE_ROOT, WORKSPACE_ROOT);
  mkdirSync(join(WORKSPACE_ROOT, ".tools"), { mode: 0o700 });
  copyFileSync(join(ACQUIRED_ROOT, "bin/pnpm.cjs"), BUILD_PNPM_PATH);
  copyDirectTree(join(ACQUIRED_ROOT, "store"), INSTALL_STORE_ROOT);
  chownPrivateTree(WORKSPACE_ROOT, BUILD_UID, BUILD_GID);
  chownPrivateTree(INSTALL_STORE_ROOT, BUILD_UID, BUILD_GID);
  const buildHome = "/tmp/z4j-dashboard-home";
  ownerPrivateNew(buildHome);
  chownSync(buildHome, BUILD_UID, BUILD_GID);
  const environment = {
    CI: "true",
    HOME: buildHome,
    LANG: "C.UTF-8",
    PATH: "/usr/local/bin:/usr/bin:/bin",
    SOURCE_DATE_EPOCH: String(dashboard.source_date_epoch),
    TZ: "UTC",
  };
  const install = runExact(generator.commands.install, WORKSPACE_ROOT, environment, {
    gid: BUILD_GID,
    uid: BUILD_UID,
  });
  requireSameProjection("/authority", protectedAuthority, "dashboard authority");
  requireSameProjection(SOURCE_ROOT, protectedSource, "dashboard source");
  requireSameProjection(ACQUIRED_ROOT, protectedAcquisition, "dashboard acquisition");
  const built = runExact(generator.commands.build, WORKSPACE_ROOT, environment, {
    gid: BUILD_GID,
    uid: BUILD_UID,
  });
  requireSameProjection("/authority", protectedAuthority, "dashboard authority");
  requireSameProjection(SOURCE_ROOT, protectedSource, "dashboard source");
  requireSameProjection(ACQUIRED_ROOT, protectedAcquisition, "dashboard acquisition");
  if (
    !canonicalJson(records(join(PAYLOAD_ROOT, "store"), new Set()), false).equals(
      canonicalJson(retainedStore, false),
    )
  ) {
    fail("retained pnpm store changed during install/build");
  }
  for (const [name, result] of [["install", install], ["build", built]]) {
    atomicWrite(join(RUN_EVIDENCE_ROOT, `${name}.stdout`), result.stdout);
    atomicWrite(join(RUN_EVIDENCE_ROOT, `${name}.stderr`), result.stderr);
  }
  atomicWrite(
    join(RUN_EVIDENCE_ROOT, "build-commands.json"),
    canonicalJson({
      commands: Object.fromEntries(
        [["build", built], ["install", install]].map(([name, result]) => [name, {
          argv: generator.commands[name],
          cwd: WORKSPACE_ROOT,
          environment,
          exit_code: 0,
          stderr: { path: `${name}.stderr`, sha256: sha256(result.stderr), size: result.stderr.length },
          stdout: { path: `${name}.stdout`, sha256: sha256(result.stdout), size: result.stdout.length },
        }]),
      ),
      format: "z4j-production-dashboard-build-run-evidence-v1",
      identity: { gid: BUILD_GID, uid: BUILD_UID },
    }),
  );
  const distSource = join(WORKSPACE_ROOT, "dist");
  copyDirectTree(distSource, join(PAYLOAD_ROOT, "dist"));
  atomicWrite(join(PAYLOAD_ROOT, "dist/.build-context"), Buffer.from("z4j-dashboard-production-v1\n"), 0o644);
  atomicWrite(join(PAYLOAD_ROOT, "dist/.build-inputs.sha256"), Buffer.from(`${projection.sha256}\n`), 0o644);
  atomicWrite(join(PAYLOAD_ROOT, "dist/.build-output.sha256"), outputMarker(join(PAYLOAD_ROOT, "dist")), 0o644);
  const selectedDist = distTree(join(PAYLOAD_ROOT, "dist"), dashboard.bundle_tree_format);
  const storeFiles = records(join(PAYLOAD_ROOT, "store"), new Set());
  const storeTree = { files: storeFiles, format: dashboard.store_tree_format };
  const components = pnpmLockComponents(regular(join(evidence, "pnpm-lock.yaml")));
  const nativeLockComponents = platformLockComponents(components, process.env.Z4J_PLATFORM);
  const installed = installedComponents(WORKSPACE_ROOT, nativeLockComponents);
  const storeReceipt = {
    format: dashboard.store_inventory_format,
    installed,
    lock_universe: components,
    native_realization: nativeLockComponents,
    platform: process.env.Z4J_PLATFORM,
    store_format: "pnpm-content-addressable-store-v10",
    store_tree_bytes: storeFiles.reduce((total, item) => total + item.size, 0),
    store_tree_sha256: sha256(canonicalJson(storeTree, false)),
  };
  atomicWrite(join(evidence, "store-inventory.json"), canonicalJson(storeReceipt));
  const buildReceipt = {
    bundle_tree_sha256: selectedDist.sha256,
    commands: generator.commands,
    environment,
    exit_code: 0,
    format: dashboard.build_receipt_format,
    node_config_digest: dashboard.node.platforms[process.env.Z4J_PLATFORM].config_digest,
    node_image: dashboard.node.image,
    node_manifest_digest: dashboard.node.platforms[process.env.Z4J_PLATFORM].manifest_digest,
    platform: process.env.Z4J_PLATFORM,
    pnpm_binary_sha256: pnpm.binary_sha256,
    pnpm_lock_sha256: sha256(regular(join(evidence, "pnpm-lock.yaml"))),
    source_projection_sha256: projection.sha256,
    run_evidence_format: "z4j-production-dashboard-build-run-evidence-v1",
    store_inventory_sha256: sha256(canonicalJson(storeReceipt)),
    working_directory: WORKSPACE_ROOT,
    execution_identity: { gid: BUILD_GID, uid: BUILD_UID },
  };
  atomicWrite(join(evidence, "build-receipt.json"), canonicalJson(buildReceipt));
  const trivyUnpack = "/tmp/z4j-trivy-unpack";
  const trivyArchivePath = join(ACQUIRED_ROOT, "evidence/trivy-archive.tgz");
  const trivyArchiveRaw = regular(trivyArchivePath);
  const trivyMembers = extractReviewedTar(
    trivyArchiveRaw,
    trivy.archive,
    trivyUnpack,
    "Trivy archive",
  );
  if (trivyMembers.filter((item) => item.path === "trivy" && item.type === "file").length !== 1) {
    fail("Trivy archive has no unique root binary");
  }
  const trivyBinary = join(trivyUnpack, "trivy");
  verifySeal(regular(trivyBinary), trivy.binary, "Trivy binary");
  copyFileSync(trivyBinary, join(evidence, "trivy"));
  chmodSync(join(evidence, "trivy"), 0o755);
  const versionTranscript = runExact([join(evidence, "trivy"), "--version"], "/authority", { LANG: "C.UTF-8", PATH: "/usr/bin:/bin", TZ: "UTC" });
  const versionRaw = Buffer.concat([versionTranscript.stdout, versionTranscript.stderr]);
  if (sha256(versionRaw) !== trivy.version_output_sha256) fail("Trivy version transcript differs");
  atomicWrite(join(evidence, "trivy-version.txt"), versionRaw);
  const databaseArchivePath = join(ACQUIRED_ROOT, "evidence/trivy-database.tar.gz");
  const databaseArchiveRaw = regular(databaseArchivePath);
  const databaseMembers = extractReviewedTar(
    databaseArchiveRaw,
    trivy.database_archive,
    join(evidence, "trivy-database"),
    "Trivy database archive",
  );
  if (databaseMembers.some((item) => item.path !== "db" && !item.path.startsWith("db/"))) {
    fail("Trivy database archive escapes its exact db root");
  }
  const cache = join(evidence, "trivy-database");
  const databaseFiles = records(cache, new Set());
  const databaseTree = { files: databaseFiles, format: "z4j-trivy-database-tree-v1" };
  if (sha256(canonicalJson(databaseTree, false)) !== trivy.database.tree_sha256) {
    fail("Trivy database tree differs");
  }
  const databaseMetadataRaw = regular(join(cache, "db/metadata.json"));
  const databaseMetadata = JSON.parse(databaseMetadataRaw.toString("utf8"));
  if (
    sha256(databaseMetadataRaw) !== trivy.database.metadata_sha256 ||
    databaseMetadata.Version !== trivy.database.schema_version ||
    databaseMetadata.DownloadedAt !== trivy.database.downloaded_at_utc ||
    databaseMetadata.UpdatedAt !== trivy.database.updated_at_utc ||
    databaseMetadata.NextUpdate !== trivy.database.next_update_utc
  ) {
    fail("Trivy database metadata differs");
  }
  const rawReport = join(RUN_EVIDENCE_ROOT, "advisory-report.raw.json");
  const sbom = join(evidence, "sbom.cyclonedx.json");
  const rawSbom = join(RUN_EVIDENCE_ROOT, "sbom.raw.cyclonedx.json");
  const scanEnvironment = { LANG: "C.UTF-8", PATH: "/usr/bin:/bin", TZ: "UTC" };
  const scanPrefix = [
    join(evidence, "trivy"),
    "fs",
    "--cache-dir",
    cache,
    "--offline-scan",
    "--skip-db-update",
    "--scanners",
    "vuln",
    "--pkg-types",
    "library",
    "--list-all-pkgs",
    "--include-dev-deps",
    "--severity",
    "HIGH,CRITICAL",
    "--ignore-unfixed=false",
  ];
  const advisoryArgv = [
    ...scanPrefix,
    "--format",
    "json",
    "--output",
    rawReport,
    WORKSPACE_ROOT,
  ];
  const sbomArgv = [
    ...scanPrefix,
    "--format",
    "cyclonedx",
    "--output",
    rawSbom,
    WORKSPACE_ROOT,
  ];
  const advisoryRun = runExact(advisoryArgv, "/authority", scanEnvironment);
  const sbomRun = runExact(sbomArgv, "/authority", scanEnvironment);
  if (
    !canonicalJson(records(cache, new Set()), false).equals(
      canonicalJson(databaseFiles, false),
    )
  ) {
    fail("offline Trivy mutated the retained database authority");
  }
  const trivySbom = JSON.parse(regular(rawSbom).toString("utf8"));
  const expectedScannedPackages = expectedTrivyPackages(components);
  const trivySbomProjection = trivyCycloneDxComponents(trivySbom, expectedScannedPackages);
  const rawReportBytes = regular(rawReport);
  const parsedReport = JSON.parse(rawReportBytes.toString("utf8"));
  const scannedPackages = trivyPnpmInventory(parsedReport, expectedScannedPackages);
  if (!canonicalJson(scannedPackages, false).equals(canonicalJson(trivySbomProjection.packages, false))) {
    fail("raw Trivy JSON and CycloneDX package identities differ");
  }
  const semanticReport = {
    findings: [],
    format: "z4j-production-dashboard-trivy-semantic-report-v2",
    packages: scannedPackages,
    platform: process.env.Z4J_PLATFORM,
    result_type: "pnpm",
  };
  const semanticReportRaw = canonicalJson(semanticReport);
  const report = join(evidence, "advisory-report.json");
  atomicWrite(report, semanticReportRaw);
  for (const [name, run] of [["advisory", advisoryRun], ["sbom", sbomRun]]) {
    atomicWrite(join(RUN_EVIDENCE_ROOT, `trivy-${name}.stdout`), run.stdout);
    atomicWrite(join(RUN_EVIDENCE_ROOT, `trivy-${name}.stderr`), run.stderr);
  }
  atomicWrite(
    join(RUN_EVIDENCE_ROOT, "trivy-commands.json"),
    canonicalJson({
      commands: {
        advisory: {
          argv: advisoryArgv,
          cwd: "/authority",
          environment: scanEnvironment,
          exit_code: 0,
          report: { path: "advisory-report.raw.json", sha256: sha256(rawReportBytes), size: rawReportBytes.length },
          stderr: { path: "trivy-advisory.stderr", sha256: sha256(advisoryRun.stderr), size: advisoryRun.stderr.length },
          stdout: { path: "trivy-advisory.stdout", sha256: sha256(advisoryRun.stdout), size: advisoryRun.stdout.length },
        },
        sbom: {
          argv: sbomArgv,
          cwd: "/authority",
          environment: scanEnvironment,
          exit_code: 0,
          report: { path: "sbom.raw.cyclonedx.json", sha256: sha256(regular(rawSbom)), size: regular(rawSbom).length },
          stderr: { path: "trivy-sbom.stderr", sha256: sha256(sbomRun.stderr), size: sbomRun.stderr.length },
          stdout: { path: "trivy-sbom.stdout", sha256: sha256(sbomRun.stdout), size: sbomRun.stdout.length },
        },
      },
      format: "z4j-production-dashboard-trivy-run-evidence-v1",
    }),
  );
  const normalizedSbom = {
    bomFormat: "CycloneDX",
    components: trivySbomProjection.components,
    metadata: {
      component: {
        hashes: [{ alg: "SHA-256", content: selectedDist.sha256 }],
        name: "z4j-dashboard",
        type: "application",
        version: "1.9.0",
      },
    },
    specVersion: "1.6",
    version: 1,
  };
  atomicWrite(sbom, canonicalJson(normalizedSbom));
  const reportRaw = regular(report);
  const advisory = {
    components_sha256: sha256(
      canonicalJson(
        scannedPackages.map((item) => [item.id, item.name, item.version, item.purl]),
        false,
      ),
    ),
    database: generator.trivy.database,
    findings: [],
    format: dashboard.advisory_receipt_format,
    platform: process.env.Z4J_PLATFORM,
    policy: { ignore_unfixed: false, list_all_packages: true, required_result_type: "pnpm", severities: ["HIGH", "CRITICAL"] },
    report: { path: "evidence/advisory-report.json", sha256: sha256(reportRaw), size: reportRaw.length },
    scanner: {
      binary_sha256: trivy.binary.sha256,
      name: "trivy",
      version: trivy.version,
      version_output_sha256: trivy.version_output_sha256,
    },
    subject_tree_sha256: selectedDist.sha256,
    run_evidence_format: "z4j-production-dashboard-trivy-run-evidence-v1",
    verdict: "pass",
  };
  atomicWrite(join(evidence, "advisory-receipt.json"), canonicalJson(advisory));
  installInventory(PAYLOAD_ROOT, process.env.Z4J_PLATFORM, dashboard);
  requireSameProjection("/authority", protectedAuthority, "dashboard authority");
  requireSameProjection(SOURCE_ROOT, protectedSource, "dashboard source");
  requireSameProjection(ACQUIRED_ROOT, protectedAcquisition, "dashboard acquisition");
}

async function main() {
  const command = process.argv[2];
  if (!["internal-acquire", "internal-build"].includes(command) || process.argv.length !== 3) {
    fail("expected exactly internal-acquire or internal-build");
  }
  const policy = loadPolicy();
  if (command === "internal-acquire") await acquire(policy);
  else await build(policy);
}

export {
  canonicalJson,
  expectedTrivyPackages,
  extractReviewedTar,
  installedComponents,
  platformLockComponents,
  pnpmLockComponents,
  protectedTreeProjection,
  records,
  requireSameProjection,
  tarMembers,
  trivyCycloneDxComponents,
  trivyPnpmInventory,
  verifyTarAuthority,
};

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 2;
  });
}
