import { afterEach, describe, expect, it } from "vitest";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  rename,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import {
  requireDemoDataTree,
  stampDemoVersions,
} from "../../scripts/stamp-demo-versions.mjs";

const dashboardRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const fixtureRoot = resolve(dashboardRoot, "src/lib/demo-data");
const repositoryRoot = resolve(dashboardRoot, "../../..");
const expectedChangedPaths = [
  "projects/django.example.com/agents.json",
  "projects/example.com/agents.json",
  "projects/fastapi.example.com/agents.json",
  "projects/tasks.example.com/agents.json",
  "system/health-system.json",
  "system/health.json",
  "system/schedulers.json",
];
const expectedVersionInventory = {
  total: 76,
  intended: 24,
  preserved: 52,
  byKey: {
    agent_version: 20,
    database_version: 1,
    model_version: 10,
    protocol_version: 20,
    python_version: 1,
    version: 3,
    version_status: 20,
    z4j_version: 1,
  },
};
const temporaryRoots: string[] = [];

async function temporaryDemoData(): Promise<string> {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "z4j-demo-version-"));
  temporaryRoots.push(temporaryRoot);
  return resolve(temporaryRoot, "demo-data");
}

async function readJson(root: string, path: string): Promise<unknown> {
  return JSON.parse(await readFile(resolve(root, path), "utf8"));
}

async function writeJson(
  root: string,
  path: string,
  document: unknown,
): Promise<void> {
  const destination = resolve(root, path);
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(
    destination,
    `${JSON.stringify(document, null, 2)}\n`,
    "utf8",
  );
}

async function jsonSnapshot(root: string): Promise<Record<string, string>> {
  const snapshot: Record<string, string> = {};
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = resolve(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(path);
      } else if (entry.isFile() && entry.name.endsWith(".json")) {
        const name = relative(root, path).split(sep).join("/");
        snapshot[name] = await readFile(path, "utf8");
      }
    }
  };
  await walk(root);
  return snapshot;
}

type JsonPathSegment = string | number;

function isIntendedCarrier(file: string, path: JsonPathSegment[]): boolean {
  return (
    (file === "system/health.json" &&
      path.length === 1 &&
      path[0] === "version") ||
    (file === "system/health-system.json" &&
      path.length === 1 &&
      path[0] === "z4j_version") ||
    (file === "system/schedulers.json" &&
      path.length === 4 &&
      path[0] === "schedulers" &&
      typeof path[1] === "number" &&
      path[2] === "info" &&
      path[3] === "version") ||
    (/^projects\/[^/]+\/agents\.json$/.test(file) &&
      path.length === 2 &&
      typeof path[0] === "number" &&
      path[1] === "agent_version")
  );
}

function versionInventory(snapshot: Record<string, string>): {
  total: number;
  intended: number;
  preserved: number;
  byKey: Record<string, number>;
  intendedValues: Record<string, unknown>;
  preservedValues: Record<string, unknown>;
} {
  let intended = 0;
  let preserved = 0;
  const byKey: Record<string, number> = {};
  const intendedValues: Record<string, unknown> = {};
  const preservedValues: Record<string, unknown> = {};
  for (const [file, source] of Object.entries(snapshot)) {
    const walk = (value: unknown, path: JsonPathSegment[] = []): void => {
      if (Array.isArray(value)) {
        value.forEach((child, index) => walk(child, [...path, index]));
      } else if (value !== null && typeof value === "object") {
        for (const [key, child] of Object.entries(value)) {
          const childPath = [...path, key];
          if (key.toLowerCase().includes("version")) {
            const location = `${file}:${JSON.stringify(childPath)}`;
            if (isIntendedCarrier(file, childPath)) {
              intended += 1;
              intendedValues[location] = child;
            } else {
              preserved += 1;
              preservedValues[location] = child;
            }
            byKey[key] = (byKey[key] ?? 0) + 1;
          }
          walk(child, childPath);
        }
      }
    };
    walk(JSON.parse(source));
  }
  return {
    total: intended + preserved,
    intended,
    preserved,
    byKey,
    intendedValues,
    preservedValues,
  };
}

function expectedStampedText(
  path: string,
  before: string,
  version: string,
): string {
  const key = path.endsWith("/agents.json")
    ? "agent_version"
    : path === "system/health-system.json"
      ? "z4j_version"
      : "version";
  const pattern = new RegExp(`("${key}"\\s*:\\s*")1\\.8\\.0(")`, "g");
  return before.replace(
    pattern,
    (_match, head, tail) => `${head}${version}${tail}`,
  );
}

afterEach(async () => {
  await Promise.all(
    temporaryRoots
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("requireDemoDataTree", () => {
  it("rejects a missing, renamed, or non-directory fixture tree", async () => {
    const root = await temporaryDemoData();
    await expect(requireDemoDataTree(root)).rejects.toThrow(
      "required demo-data tree is unavailable",
    );

    await mkdir(root);
    const renamed = `${root}-renamed`;
    await rename(root, renamed);
    await expect(requireDemoDataTree(root)).rejects.toThrow(
      "required demo-data tree is unavailable",
    );

    await writeFile(root, "not a directory", "utf8");
    await expect(requireDemoDataTree(root)).rejects.toThrow(
      "required demo-data tree is not a real directory",
    );
  });

  it("rejects an unreadable fixture tree", async () => {
    if (process.platform === "win32") return;
    const root = await temporaryDemoData();
    await mkdir(root);
    await chmod(root, 0o000);
    try {
      await expect(requireDemoDataTree(root)).rejects.toThrow(
        "required demo-data tree is not readable",
      );
    } finally {
      await chmod(root, 0o700);
    }
  });

  it("binds the mandatory tree check before copy and exact stamping", async () => {
    const source = await readFile(
      resolve(dashboardRoot, "scripts/build-demo.mjs"),
      "utf8",
    );
    const requiredAt = source.indexOf("await requireDemoDataTree(dataSrc);");
    const copyAt = source.indexOf("await cp(dataSrc, dataDst", requiredAt);
    const stampAt = source.indexOf(
      "stampDemoVersions(dataDst, version",
      copyAt,
    );
    expect(requiredAt).toBeGreaterThan(-1);
    expect(copyAt).toBeGreaterThan(requiredAt);
    expect(stampAt).toBeGreaterThan(copyAt);
    expect(source).not.toContain("hasDataTree");
    expect(source).toMatch(/files:\s*7,[\s\S]*fields:\s*24/);
  });
});

describe("stampDemoVersions", () => {
  it("stamps the exact 24-field inventory and is byte-idempotent", async () => {
    const root = await temporaryDemoData();
    await cp(fixtureRoot, root, { recursive: true });
    const version = (
      await readFile(resolve(repositoryRoot, "VERSION"), "utf8")
    ).trim();
    expect(version).toBe("1.10.0");
    const before = await jsonSnapshot(root);
    const {
      intendedValues: beforeIntendedValues,
      preservedValues: beforePreservedValues,
      ...beforeInventory
    } = versionInventory(before);
    expect(beforeInventory).toEqual(expectedVersionInventory);
    expect(Object.keys(beforeIntendedValues)).toHaveLength(24);
    expect(new Set(Object.values(beforeIntendedValues))).toEqual(
      new Set(["1.8.0"]),
    );
    expect(Object.keys(beforePreservedValues)).toHaveLength(52);
    for (const path of expectedChangedPaths) {
      expect(before[path]).not.toContain("\\");
    }

    const first = await stampDemoVersions(root, version, {
      files: 7,
      fields: 24,
    });
    const afterFirst = await jsonSnapshot(root);

    expect(first).toEqual({
      files: 7,
      fields: 24,
      changedFiles: 7,
      changedFields: 24,
    });
    expect(Object.keys(afterFirst).sort()).toEqual(Object.keys(before).sort());
    expect(
      Object.keys(before)
        .filter((path) => before[path] !== afterFirst[path])
        .sort(),
    ).toEqual(expectedChangedPaths);
    for (const path of expectedChangedPaths) {
      expect(afterFirst[path]).toBe(
        expectedStampedText(path, before[path], version),
      );
    }
    const {
      intendedValues: afterIntendedValues,
      preservedValues: afterPreservedValues,
      ...afterInventory
    } = versionInventory(afterFirst);
    expect(afterInventory).toEqual(expectedVersionInventory);
    expect(Object.keys(afterIntendedValues).sort()).toEqual(
      Object.keys(beforeIntendedValues).sort(),
    );
    expect(new Set(Object.values(afterIntendedValues))).toEqual(
      new Set([version]),
    );
    expect(afterPreservedValues).toEqual(beforePreservedValues);
    const system = JSON.parse(afterFirst["system/health-system.json"]) as {
      z4j_version: string;
      python_version: string;
      database_version: string;
      packages: Record<string, string>;
    };
    expect(system.z4j_version).toBe("1.10.0");
    expect(system.python_version).toBe("3.14.0");
    expect(system.database_version).toBe(
      "PostgreSQL 18.3 on x86_64-pc-linux-gnu",
    );
    expect(system.packages).toEqual({
      fastapi: "0.136.0",
      uvicorn: "0.45.0",
      sqlalchemy: "2.0.49",
      pydantic: "2.13.3",
      celery: "5.5.3",
    });

    const second = await stampDemoVersions(root, version, {
      files: 7,
      fields: 24,
    });
    expect(second).toEqual({
      files: 7,
      fields: 24,
      changedFiles: 0,
      changedFields: 0,
    });
    expect(await jsonSnapshot(root)).toEqual(afterFirst);
  });

  it("rejects build-inventory drift before writing any fixture", async () => {
    const root = await temporaryDemoData();
    await cp(fixtureRoot, root, { recursive: true });
    const before = await jsonSnapshot(root);

    await expect(
      stampDemoVersions(root, "1.9.0", {
        files: 8,
        fields: 24,
      }),
    ).rejects.toThrow(
      "unexpected z4j version inventory: 24 field(s) in 7 file(s); " +
        "expected 24 field(s) in 8 file(s)",
    );
    expect(await jsonSnapshot(root)).toEqual(before);
  });

  it("preserves semver-shaped non-z4j fields outside the allowlist", async () => {
    const root = await temporaryDemoData();
    await writeJson(root, "system/health.json", {
      status: "ok",
      version: "1.8.0",
    });
    await writeJson(root, "system/health-system.json", {
      z4j_version: "1.8.0",
      python_version: "3.14.0",
      database_version: "18.3.0",
      protocol_version: "2.0.0",
    });
    await writeJson(root, "system/schedulers.json", {
      schedulers: [
        {
          info: {
            version: "1.8.0",
            protocol_version: "2.0.0",
          },
        },
      ],
    });
    await writeJson(root, "projects/example.com/agents.json", [
      {
        agent_version: "1.8.0",
        protocol_version: "2.0.0",
        model_version: "3.2.0",
        version_status: "3.1.0",
      },
    ]);
    await writeJson(root, "misc/component.json", {
      version: "4.5.6",
      z4j_version: "7.8.9",
    });

    const result = await stampDemoVersions(root, "9.8.7");

    expect(result).toEqual({
      files: 4,
      fields: 4,
      changedFiles: 4,
      changedFields: 4,
    });
    expect(await readJson(root, "system/health-system.json")).toEqual({
      z4j_version: "9.8.7",
      python_version: "3.14.0",
      database_version: "18.3.0",
      protocol_version: "2.0.0",
    });
    expect(await readJson(root, "projects/example.com/agents.json")).toEqual([
      {
        agent_version: "9.8.7",
        protocol_version: "2.0.0",
        model_version: "3.2.0",
        version_status: "3.1.0",
      },
    ]);
    expect(await readJson(root, "system/schedulers.json")).toEqual({
      schedulers: [
        {
          info: {
            version: "9.8.7",
            protocol_version: "2.0.0",
          },
        },
      ],
    });
    expect(await readJson(root, "misc/component.json")).toEqual({
      version: "4.5.6",
      z4j_version: "7.8.9",
    });
  });

  it.each([
    [
      "a duplicate allowlisted key already at the target",
      '{"status":"ok","version":"1.9.0","version":"1.9.0"}\n',
    ],
    [
      "a duplicate non-semver shadow before the allowlisted key",
      '{"status":"ok","version":"not-semver","version":"1.9.0"}\n',
    ],
    [
      "a nested unmodeled same-key carrier already at the target",
      '{"status":"ok","version":"1.9.0","metadata":{"version":"1.9.0"}}\n',
    ],
  ])("rejects %s", async (_kind, healthSource) => {
    const root = await temporaryDemoData();
    await writeJson(root, "system/health-system.json", {
      z4j_version: "1.9.0",
    });
    await writeJson(root, "system/schedulers.json", {
      schedulers: [{ info: { version: "1.9.0" } }],
    });
    await writeJson(root, "projects/example.com/agents.json", [
      { agent_version: "1.9.0" },
    ]);
    await writeFile(resolve(root, "system/health.json"), healthSource, "utf8");

    const before = await jsonSnapshot(root);
    await expect(stampDemoVersions(root, "1.9.0")).rejects.toThrow(
      "expected 1 textual version carrier(s), found 2",
    );
    expect(await jsonSnapshot(root)).toEqual(before);
  });

  it.each([
    [
      "a fully escaped carrier key",
      String.raw`{"status":"ok","\u0076ersion":"1.8.0"}` + "\n",
    ],
    [
      "a partially escaped carrier key",
      String.raw`{"status":"ok","ver\u0073ion":"1.8.0"}` + "\n",
    ],
    [
      "a literal key followed by an escaped duplicate",
      String.raw`{"version":"1.8.0","\u0076ersion":"1.8.0"}` + "\n",
    ],
    [
      "an escaped key followed by a literal duplicate",
      String.raw`{"\u0076ersion":"1.8.0","version":"1.8.0"}` + "\n",
    ],
    [
      "an escaped top-level key with a nested literal shadow",
      String.raw`{"\u0076ersion":"1.8.0","metadata":{"version":"1.8.0"}}` +
        "\n",
    ],
    [
      "a legitimate escaped non-key value",
      String.raw`{"status":"line\nbreak","url":"https:\/\/example.com","version":"1.8.0"}` +
        "\n",
    ],
  ])("rejects %s", async (_kind, healthSource) => {
    const root = await temporaryDemoData();
    await writeJson(root, "system/health-system.json", {
      z4j_version: "1.9.0",
    });
    await writeJson(root, "system/schedulers.json", {
      schedulers: [{ info: { version: "1.9.0" } }],
    });
    await writeJson(root, "projects/example.com/agents.json", [
      { agent_version: "1.9.0" },
    ]);
    await mkdir(resolve(root, "system"), { recursive: true });
    await writeFile(resolve(root, "system/health.json"), healthSource, "utf8");

    const before = await jsonSnapshot(root);
    await expect(stampDemoVersions(root, "1.9.0")).rejects.toThrow(
      "system/health.json contains a JSON escape",
    );
    expect(await jsonSnapshot(root)).toEqual(before);
  });

  it("fails closed when a required carrier is missing", async () => {
    const root = await temporaryDemoData();
    await writeJson(root, "system/health.json", { status: "ok" });
    await writeJson(root, "system/health-system.json", {
      z4j_version: "1.8.0",
    });
    await writeJson(root, "system/schedulers.json", {
      schedulers: [{ info: { version: "1.8.0" } }],
    });
    await writeJson(root, "projects/example.com/agents.json", [
      { agent_version: "1.8.0" },
    ]);

    const before = await jsonSnapshot(root);
    await expect(stampDemoVersions(root, "1.9.0")).rejects.toThrow(
      "system/health.json.version must be a bare release number",
    );
    expect(await jsonSnapshot(root)).toEqual(before);
  });
});
