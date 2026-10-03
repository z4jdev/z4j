/**
 * demo.z4j.com is a static Cloudflare Pages site. Pages drops any _redirects
 * line it rejects without a word, and `wrangler pages deploy` uploads the file
 * unparsed, which is how a _redirects with zero working rules once shipped.
 * These tests pin the generated routing and header files and the validator
 * build-demo.mjs runs against the finished dist-demo/.
 */
import { afterEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  BUILD_WRITTEN_ENTRIES,
  MAX_DYNAMIC_RULES,
  MAX_STATIC_RULES,
  barePrefixOfRoute,
  buildHeaders,
  buildRedirects,
  extractRouteManifestPaths,
  findDemoPagesViolations,
  parseRedirects,
  ruleSourceForRoute,
  validateDemoPagesDist,
} from "../../scripts/demo-pages-config.mjs";

const dashboardRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

// The top level of dist-demo/ once build-demo.mjs has finished.
const DIST_ENTRIES = [
  "404.html",
  "THIRD-PARTY-NOTICES.txt",
  "_headers",
  "_redirects",
  "demo-data",
  "favicon.svg",
  "index.html",
  "logos",
  "route-manifest.json",
  "static",
];

// A slice of FileRoutesByFullPath, deliberately out of order: the root, plain
// paths, index routes with a trailing slash, a non-nested route
// (login_.mfa.tsx is served at /login/mfa) and dynamic routes under
// /projects/$slug.
const MANIFEST = [
  "/",
  "/login",
  "/settings",
  "/login/mfa",
  "/admin/users",
  "/projects/$slug",
  "/settings/account",
  "/settings/",
  "/projects/$slug/tasks",
  "/settings/notifications",
  "/projects/$slug/",
  "/settings/notifications/",
  "/projects/$slug/tasks/$engine/$taskId",
];

const RULES = [
  "/admin/users / 200",
  "/login / 200",
  "/login/mfa / 200",
  "/settings / 200",
  "/settings/account / 200",
  "/settings/notifications / 200",
  "/projects/* / 200",
];

const CSP =
  "default-src 'self'; script-src 'self' 'sha256-AAAA'; frame-ancestors 'none'";
const INDEX_HTML =
  '<!doctype html><script data-cfasync="false">theme()</script>' +
  '<script data-cfasync="false" type="module" src="/static/index-abc.js"></script>';

// What every earlier build wrote. Pages rejected both _redirects lines.
const OLD_REDIRECTS =
  "/static/*    /index.html   404\n/*    /index.html   200\n";
const OLD_HEADERS = [
  "/static/*",
  "  Cache-Control: public, max-age=31536000, immutable",
  "",
  "/demo-data/*",
  "  Cache-Control: public, max-age=300",
  "",
  "/*",
  "  X-Frame-Options: DENY",
  "  X-Content-Type-Options: nosniff",
  "  Referrer-Policy: strict-origin-when-cross-origin",
  `  Content-Security-Policy: ${CSP}`,
  "",
].join("\n");

interface ParsedRedirects {
  rules: {
    lineNumber: number;
    from: string;
    to: string;
    status: number;
    dynamic: boolean;
    demoted: boolean;
  }[];
  invalid: { lineNumber: number; line: string; message: string }[];
}

interface DemoDist {
  entries: string[];
  manifestPaths: string[] | null;
  redirects: string | null;
  headers: string | null;
  indexHtml: string | null;
  notFoundHtml: string | null;
  csp?: string;
}

const parse = (text: string): ParsedRedirects =>
  parseRedirects(text) as ParsedRedirects;

const rulesOf = (text: string): string[] =>
  text.split("\n").filter((line) => line !== "" && !line.startsWith("#"));

function goodDist(overrides: Partial<DemoDist> = {}): DemoDist {
  return {
    entries: DIST_ENTRIES,
    manifestPaths: MANIFEST,
    redirects: buildRedirects(MANIFEST, DIST_ENTRIES),
    headers: buildHeaders(CSP),
    indexHtml: INDEX_HTML,
    notFoundHtml: INDEX_HTML,
    csp: CSP,
    ...overrides,
  };
}

// The generated _redirects with its rule lines passed through `edit`.
function editRules(edit: (rules: string[]) => string[]): string {
  const text = buildRedirects(MANIFEST, DIST_ENTRIES);
  const comments = text.split("\n").filter((line) => line.startsWith("#"));
  return [...comments, ...edit(rulesOf(text)), ""].join("\n");
}

const replaceRule = (from: string, to: string) =>
  editRules((rules) => rules.map((rule) => (rule === from ? to : rule)));

function expectViolations(violations: string[], patterns: RegExp[]): void {
  for (const pattern of patterns) {
    expect(
      violations.some((violation) => pattern.test(violation)),
      `${pattern} in ${JSON.stringify(violations, null, 2)}`,
    ).toBe(true);
  }
}

const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryRoots
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("extractRouteManifestPaths", () => {
  it("lists every full path of the generated router", () => {
    const source = [
      "export interface FileRoutesByFullPath {",
      "  '/': typeof IndexRoute",
      "  '/login/mfa': typeof LoginMfaRoute",
      "  '/projects/$slug/': typeof ProjectsSlugIndexRoute",
      "}",
    ].join("\n");
    expect(extractRouteManifestPaths(source)).toEqual([
      "/",
      "/login/mfa",
      "/projects/$slug/",
    ]);
    expect(() => extractRouteManifestPaths("export const x = 1;\n")).toThrow(
      "Missing FileRoutesByFullPath in generated router",
    );
  });
});

describe("ruleSourceForRoute", () => {
  it.each<[string, string | null]>([
    ["/", null],
    ["/login", "/login"],
    ["/login/mfa", "/login/mfa"],
    ["/settings/", "/settings"],
    ["/settings/notifications/", "/settings/notifications"],
    ["/projects/$slug", "/projects/*"],
    ["/projects/$slug/", "/projects/*"],
    ["/projects/$slug/settings/notifications/", "/projects/*"],
    ["/projects/$slug/tasks/$engine/$taskId", "/projects/*"],
    ["/files/$", "/files/*"],
    ["/files/{$}", "/files/*"],
    ["/docs/{-$lang}", "/docs/*"],
  ])("maps %j to %j", (path, source) => {
    expect(ruleSourceForRoute(path)).toBe(source);
  });

  it.each(["/$slug", "/$slug/tasks", "/$", "/{-$lang}"])(
    "refuses %j, whose rule would be the catch-all",
    (path) => {
      expect(() => ruleSourceForRoute(path)).toThrow(
        `route ${path} has no static prefix; its rule would be the catch-all "/*"`,
      );
    },
  );

  it.each([
    "login",
    "",
    "//",
    "/settings//",
    "/a b",
    "/a:b",
    "/a*",
    "/a#b",
    "/a?b",
    "/./x",
    "/../x",
  ])("refuses %j, which _redirects cannot express", (path) => {
    expect(() => ruleSourceForRoute(path)).toThrow(
      /must start with "\/"|cannot express/,
    );
  });
});

describe("barePrefixOfRoute", () => {
  // TanStack Router skips an optional segment and lets a splat with nothing
  // around it capture an empty rest, so such a route also answers its prefix.
  it.each<[string, string | null]>([
    ["/", null],
    ["/login", null],
    ["/settings/", null],
    ["/projects/$slug", null],
    ["/projects/$slug/", null],
    ["/projects/$slug/{-$tab}", null],
    ["/docs/{-$lang}/intro", null],
    ["/files/raw{$}", null],
    ["/docs/{-$lang}", "/docs"],
    ["/docs/{-$lang}/", "/docs"],
    ["/docs/{-$lang}/{-$version}", "/docs"],
    ["/docs/v{-$version}.html", "/docs"],
    ["/files/$", "/files"],
    ["/files/{$}", "/files"],
  ])("maps %j to %j", (path, bare) => {
    expect(barePrefixOfRoute(path)).toBe(bare);
  });
});

describe("buildRedirects", () => {
  it("writes comments, then sorted exact rules, then sorted splat rules", () => {
    const text = buildRedirects(MANIFEST, DIST_ENTRIES);
    const lines = text.split("\n");
    const firstRule = lines.findIndex((line) => !line.startsWith("#"));
    expect(firstRule).toBeGreaterThan(0);
    expect(lines.slice(firstRule, -1)).toEqual(RULES);
    expect(lines.at(-1)).toBe("");
    expect(text).not.toMatch(/\r|\t| {2}/);
  });

  it("does not depend on manifest order or repeats", () => {
    const expected = buildRedirects(MANIFEST, DIST_ENTRIES);
    expect(
      buildRedirects([...MANIFEST].reverse().concat(MANIFEST), DIST_ENTRIES),
    ).toBe(expected);
    expect(buildRedirects(MANIFEST, [...DIST_ENTRIES].reverse())).toBe(
      expected,
    );
  });

  it("serves every path of the real router", async () => {
    const source = await readFile(
      resolve(dashboardRoot, "src/routeTree.gen.ts"),
      "utf8",
    );
    const paths = extractRouteManifestPaths(source);
    expect(paths).toContain("/projects/$slug/issues");
    const redirects = buildRedirects(paths, DIST_ENTRIES);
    const rules = rulesOf(redirects);
    expect(rules).toContain("/login/mfa / 200");
    expect(rules).toContain("/settings / 200");
    expect(rules).toContain("/projects/* / 200");
    for (const rule of rules) {
      expect(rule).toMatch(/^\/[^*\s]+(?:\/\*)? \/ 200$/);
    }
    expect(
      findDemoPagesViolations(goodDist({ manifestPaths: paths, redirects })),
    ).toEqual([]);
  });

  it("refuses a dynamic route with no static prefix", () => {
    expect(() =>
      buildRedirects(["/login", "/$slug/tasks"], DIST_ENTRIES),
    ).toThrow('its rule would be the catch-all "/*"');
  });

  it.each([
    ["/static/$file", "static"],
    ["/demo-data/projects", "demo-data"],
    ["/logos/$name", "logos"],
    ["/favicon.svg", "favicon.svg"],
    ["/route-manifest.json", "route-manifest.json"],
    ["/THIRD-PARTY-NOTICES.txt", "THIRD-PARTY-NOTICES.txt"],
    ["/_headers", "_headers"],
    ["/_redirects", "_redirects"],
    ["/index", "index.html"],
    ["/index.html", "index.html"],
    ["/404", "404.html"],
    ["/404/$code", "404.html"],
  ])("refuses %j, which would hide the real dist entry %s", (path, entry) => {
    expect(() => buildRedirects(["/login", path], DIST_ENTRIES)).toThrow(
      `hiding the real dist entry ${entry}`,
    );
  });

  it("refuses a route named after a file the build writes after Vite", () => {
    const viteOutput = [
      "THIRD-PARTY-NOTICES.txt",
      "demo-data",
      "favicon.svg",
      "index.html",
      "logos",
      "static",
    ];
    expect(() => buildRedirects(["/404"], viteOutput)).not.toThrow();
    expect(() =>
      buildRedirects(["/404"], [...viteOutput, ...BUILD_WRITTEN_ENTRIES]),
    ).toThrow("hiding the real dist entry 404.html");
  });

  it("refuses more rules than Pages accepts", () => {
    const statics = Array.from(
      { length: MAX_STATIC_RULES + 1 },
      (_, index) => `/s${index}`,
    );
    expect(() =>
      buildRedirects([...statics.slice(1), ...statics.slice(1)], DIST_ENTRIES),
    ).not.toThrow();
    expect(() => buildRedirects(statics, DIST_ENTRIES)).toThrow(
      `${MAX_STATIC_RULES + 1} static rules exceed the Pages limit of ${MAX_STATIC_RULES}`,
    );
    const dynamics = Array.from(
      { length: MAX_DYNAMIC_RULES + 1 },
      (_, index) => `/d${index}/$id`,
    );
    expect(() =>
      buildRedirects(dynamics.slice(1), DIST_ENTRIES),
    ).not.toThrow();
    expect(() => buildRedirects(dynamics, DIST_ENTRIES)).toThrow(
      `${MAX_DYNAMIC_RULES + 1} dynamic rules exceed the Pages limit of ${MAX_DYNAMIC_RULES}`,
    );
  });

  it("refuses an empty manifest", () => {
    expect(() => buildRedirects([], DIST_ENTRIES)).toThrow(
      "route manifest has no paths",
    );
  });

  it.each([
    ["/docs/{-$lang}", "/docs"],
    ["/docs/{-$lang}/{-$version}", "/docs"],
    ["/files/$", "/files"],
    ["/files/{$}", "/files"],
  ])("refuses %j, whose bare prefix %s no rule would serve", (path, bare) => {
    expect(() => buildRedirects(["/login", path], DIST_ENTRIES)).toThrow(
      `route ${path} also serves ${bare}, which ${bare}/* does not match ` +
        "and no static route covers",
    );
  });

  it("serves a bare prefix through the exact rule of a static route", () => {
    expect(
      rulesOf(
        buildRedirects(
          ["/files/$", "/docs/{-$lang}", "/files", "/docs/"],
          DIST_ENTRIES,
        ),
      ),
    ).toEqual(["/docs / 200", "/files / 200", "/docs/* / 200", "/files/* / 200"]);
  });
});

describe("buildHeaders", () => {
  it("writes the catch-all first, then detaches Cache-Control for assets and data", () => {
    expect(buildHeaders(CSP)).toBe(
      "/*\n" +
        "  Cache-Control: public, max-age=0, must-revalidate, no-transform\n" +
        "  X-Frame-Options: DENY\n" +
        "  X-Content-Type-Options: nosniff\n" +
        "  Referrer-Policy: strict-origin-when-cross-origin\n" +
        "  X-Robots-Tag: noindex\n" +
        `  Content-Security-Policy: ${CSP}\n` +
        "\n" +
        "/static/*\n" +
        "  ! Cache-Control\n" +
        "  Cache-Control: public, max-age=31536000, immutable\n" +
        "\n" +
        "/demo-data/*\n" +
        "  ! Cache-Control\n" +
        "  Cache-Control: public, max-age=300\n",
    );
  });

  it.each(["", "   ", "default-src 'self';\nscript-src 'none'", "a\rb"])(
    "refuses the policy %j",
    (csp) => {
      expect(() => buildHeaders(csp)).toThrow(
        "Content-Security-Policy must be one non-empty line",
      );
    },
  );
});

describe("parseRedirects", () => {
  it("reads the old two-line file as zero rules, as Pages did", () => {
    const { rules, invalid } = parse(OLD_REDIRECTS);
    expect(rules).toEqual([]);
    expect(invalid.map((line) => line.lineNumber)).toEqual([1, 2]);
    expect(invalid[0].message).toMatch(/status 404 is not one of/);
    expect(invalid[1].message).toMatch(/would loop/);
  });

  it("skips the comments and reads each generated rule", () => {
    const { rules, invalid } = parse(buildRedirects(MANIFEST, DIST_ENTRIES));
    expect(invalid).toEqual([]);
    expect(
      rules.map((rule) => `${rule.from} ${rule.to} ${rule.status}`),
    ).toEqual(RULES);
    expect(rules.filter((rule) => rule.dynamic).map((rule) => rule.from)).toEqual(
      ["/projects/*"],
    );
    expect(rules.some((rule) => rule.demoted)).toBe(false);
  });

  it("demotes a static rule that follows a dynamic one", () => {
    const { rules } = parse("/projects/* / 200\n/login / 200\n");
    expect(rules.map((rule) => [rule.from, rule.dynamic, rule.demoted])).toEqual(
      [
        ["/projects/*", true, false],
        ["/login", false, true],
      ],
    );
  });

  it("ignores a splat rewrite to /index.html as a loop", () => {
    const { rules, invalid } = parse("/projects/* /index.html 200\n");
    expect(rules).toEqual([]);
    expect(invalid[0].message).toMatch(/would loop/);
  });

  it("ignores repeats, bad field counts and statuses Pages does not permit", () => {
    const { rules, invalid } = parse(
      [
        "/login / 200",
        "/login / 200",
        "/reset",
        "/a / 200 extra",
        "/b / 404",
        "/c / 200",
        "",
      ].join("\n"),
    );
    expect(rules.map((rule) => rule.from)).toEqual(["/login", "/c"]);
    expect(invalid.map((line) => line.lineNumber)).toEqual([2, 3, 4, 5]);
  });

  it("drops the rules past each Pages limit", () => {
    const statics = Array.from(
      { length: MAX_STATIC_RULES + 1 },
      (_, index) => `/s${index} / 200`,
    );
    const dynamics = Array.from(
      { length: MAX_DYNAMIC_RULES + 2 },
      (_, index) => `/d${index}/* / 200`,
    );
    const { rules, invalid } = parse([...statics, ...dynamics, ""].join("\n"));
    expect(rules).toHaveLength(MAX_STATIC_RULES + MAX_DYNAMIC_RULES);
    expect(invalid.map((line) => line.lineNumber)).toEqual([
      MAX_STATIC_RULES + 1,
      MAX_STATIC_RULES + 1 + MAX_DYNAMIC_RULES + 1,
    ]);
  });
});

describe("findDemoPagesViolations", () => {
  it("accepts what the generator writes, with or without the build's CSP", () => {
    expect(findDemoPagesViolations(goodDist())).toEqual([]);
    expect(findDemoPagesViolations(goodDist({ csp: undefined }))).toEqual([]);
  });

  it("accepts a route that also serves its bare prefix when a static route covers it", () => {
    const manifestPaths = [...MANIFEST, "/files", "/files/$"];
    expect(
      findDemoPagesViolations(
        goodDist({
          manifestPaths,
          redirects: buildRedirects(manifestPaths, DIST_ENTRIES),
        }),
      ),
    ).toEqual([]);
  });

  it.each<[string, Partial<DemoDist>, RegExp[]]>([
    [
      "the old two-line _redirects",
      { redirects: OLD_REDIRECTS },
      [
        /_redirects line 1 .*Pages ignores it, status 404 is not one of/,
        /_redirects line 2 .*Pages ignores it, it would loop/,
        /route \/login is not covered/,
        /route \/projects\/\$slug\/tasks is not covered/,
      ],
    ],
    [
      "a splat rewrite to /index.html",
      { redirects: replaceRule("/projects/* / 200", "/projects/* /index.html 200") },
      [/would loop/, /route \/projects\/\$slug is not covered/],
    ],
    [
      "a static rewrite to /index.html",
      { redirects: replaceRule("/login / 200", "/login /index.html 200") },
      [/target \/index\.html, expected "\/"/, /route \/login is not covered/],
    ],
    [
      "a 404 status",
      { redirects: replaceRule("/login / 200", "/login / 404") },
      [
        /"\/login \/ 404": Pages ignores it, status 404/,
        /route \/login is not covered/,
      ],
    ],
    [
      "a redirect status",
      { redirects: replaceRule("/login / 200", "/login / 301") },
      [/status 301, expected 200/, /route \/login is not covered/],
    ],
    [
      "a catch-all rule",
      { redirects: editRules((rules) => [...rules, "/* / 200"]) },
      [/a catch-all "\/\*" rule is not allowed/],
    ],
    [
      "a static rule after a dynamic rule",
      {
        redirects: editRules((rules) => [
          ...rules.filter((rule) => rule !== "/login / 200"),
          "/login / 200",
        ]),
      },
      [/a static rule after a dynamic rule/],
    ],
    [
      "an uncovered manifest path",
      {
        redirects: editRules((rules) =>
          rules.filter((rule) => rule !== "/admin/users / 200"),
        ),
      },
      [/route \/admin\/users is not covered/],
    ],
    [
      "a rule over a real file",
      { redirects: editRules((rules) => ["/favicon.svg / 200", ...rules]) },
      [/hides the real dist entry favicon\.svg/],
    ],
    [
      "a placeholder rule",
      { redirects: replaceRule("/projects/* / 200", "/projects/:slug / 200") },
      [
        /neither an exact route path nor "<prefix>\/\*"/,
        /route \/projects\/\$slug\/tasks is not covered/,
      ],
    ],
    [
      "a splat route whose bare prefix has no rule",
      {
        manifestPaths: [...MANIFEST, "/files", "/files/$"],
        redirects: editRules((rules) => [...rules, "/files/* / 200"]),
      },
      [
        /route \/files is not covered/,
        /route \/files\/\$ is not covered by a rewrite to "\/" \(Pages answers \/files with 404\)/,
      ],
    ],
    [
      "an optional-parameter route whose bare prefix has no rule",
      {
        manifestPaths: [...MANIFEST, "/docs/{-$lang}"],
        redirects: editRules((rules) => [...rules, "/docs/* / 200"]),
      },
      [
        /route \/docs\/\{-\$lang\} is not covered by a rewrite to "\/" \(Pages answers \/docs with 404\)/,
      ],
    ],
    [
      "spacing the generator never writes",
      {
        redirects: editRules((rules) =>
          rules.map((rule) => rule.replace(/ /g, "  ")),
        ),
      },
      [
        /_redirects line 3 is "\/admin\/users {2}\/ {2}200", expected "\/admin\/users \/ 200"/,
      ],
    ],
    ["a missing _redirects", { redirects: null }, [/_redirects is missing/]],
    [
      "a route the rules cannot express",
      { manifestPaths: [...MANIFEST, "/$slug/tasks"] },
      [/route-manifest\.json: route \/\$slug\/tasks has no static prefix/],
    ],
    [
      "a missing route manifest",
      { manifestPaths: null },
      [/route-manifest\.json has no paths/],
    ],
    [
      "a missing 404.html",
      { notFoundHtml: null },
      [/404\.html is missing, so Pages falls back to single-page-application mode/],
    ],
    [
      "a 404.html copied before the Rocket Loader opt-out",
      { notFoundHtml: INDEX_HTML.replaceAll(' data-cfasync="false"', "") },
      [/404\.html is not a byte copy of index\.html/],
    ],
    ["a missing index.html", { indexHtml: null }, [/index\.html is missing/]],
    [
      "HTML without no-transform",
      {
        headers: buildHeaders(CSP).replace(
          "must-revalidate, no-transform",
          "must-revalidate",
        ),
      },
      [/_headers line 2 is .*, expected .*must-revalidate, no-transform"/],
    ],
    [
      "/static/* without immutable",
      {
        headers: buildHeaders(CSP).replace(
          "max-age=31536000, immutable",
          "max-age=31536000",
        ),
      },
      [/_headers line 11 is .*, expected .*max-age=31536000, immutable"/],
    ],
    [
      "/static/* without the Cache-Control detach",
      { headers: buildHeaders(CSP).replace("  ! Cache-Control\n", "") },
      [/_headers line 10 is .*, expected " {2}! Cache-Control"/],
    ],
    [
      "the old _headers with the catch-all last",
      { headers: OLD_HEADERS },
      [/_headers line 1 is "\/static\/\*", expected "\/\*"/],
    ],
    [
      "a policy other than the build's",
      { headers: buildHeaders("default-src 'self'") },
      [/_headers line 7 is " {2}Content-Security-Policy: default-src 'self'"/],
    ],
    [
      "_headers without a policy",
      {
        headers: buildHeaders(CSP).replace(
          /^ {2}Content-Security-Policy: .*\n/m,
          "",
        ),
        csp: undefined,
      },
      [/_headers has no Content-Security-Policy/],
    ],
    [
      "_headers with CRLF line endings",
      { headers: buildHeaders(CSP).replace(/\n/g, "\r\n") },
      [/_headers line 1 is "\/\*\\r", expected "\/\*"/],
    ],
    ["a missing _headers", { headers: null }, [/_headers is missing/]],
  ])("reports %s", (_kind, overrides, patterns) => {
    expectViolations(findDemoPagesViolations(goodDist(overrides)), patterns);
  });
});

describe("validateDemoPagesDist", () => {
  async function writeDist(): Promise<string> {
    const root = await mkdtemp(join(tmpdir(), "z4j-demo-pages-"));
    temporaryRoots.push(root);
    for (const directory of ["demo-data", "logos", "static"]) {
      await mkdir(join(root, directory));
    }
    const files: Record<string, string> = {
      "404.html": INDEX_HTML,
      "THIRD-PARTY-NOTICES.txt": "notices\n",
      _headers: buildHeaders(CSP),
      _redirects: buildRedirects(MANIFEST, DIST_ENTRIES),
      "favicon.svg": "<svg/>\n",
      "index.html": INDEX_HTML,
      "route-manifest.json": `${JSON.stringify({ paths: MANIFEST }, null, 2)}\n`,
    };
    for (const [name, text] of Object.entries(files)) {
      await writeFile(join(root, name), text, "utf8");
    }
    return root;
  }

  it("accepts a finished dist on disk", async () => {
    const root = await writeDist();
    expect(await validateDemoPagesDist(root, { csp: CSP })).toEqual([]);
    expect(await validateDemoPagesDist(root)).toEqual([]);
  });

  it("reports a missing 404.html and a route added without a rule", async () => {
    const root = await writeDist();
    await rm(join(root, "404.html"));
    await writeFile(
      join(root, "route-manifest.json"),
      JSON.stringify({ paths: [...MANIFEST, "/admin/schedulers"] }),
      "utf8",
    );
    expectViolations(await validateDemoPagesDist(root, { csp: CSP }), [
      /404\.html is missing/,
      /route \/admin\/schedulers is not covered/,
    ]);
  });

  it("reports an unreadable route manifest", async () => {
    const root = await writeDist();
    await writeFile(join(root, "route-manifest.json"), "{", "utf8");
    expectViolations(await validateDemoPagesDist(root, { csp: CSP }), [
      /route-manifest\.json has no paths/,
    ]);
  });
});

describe("build-demo.mjs", () => {
  it("copies 404.html from the final index.html and validates the dist last", async () => {
    const source = await readFile(
      resolve(dashboardRoot, "scripts/build-demo.mjs"),
      "utf8",
    );
    const manifestAt = source.indexOf("extractRouteManifestPaths(routeSource)");
    const redirectsAt = source.indexOf("buildRedirects(paths, distEntries)");
    const cfasyncAt = source.indexOf(
      "await writeFile(indexHtmlPath, guardedIndexHtml",
    );
    const cspAt = source.indexOf("const csp = [");
    const notFoundAt = source.indexOf("await copyFile(indexHtmlPath,");
    const headersAt = source.indexOf("buildHeaders(csp)");
    const validateAt = source.indexOf(
      "await validateDemoPagesDist(distDemoPath, { csp })",
    );
    for (const at of [
      manifestAt,
      redirectsAt,
      cfasyncAt,
      cspAt,
      notFoundAt,
      headersAt,
      validateAt,
    ]) {
      expect(at).toBeGreaterThan(-1);
    }
    expect(redirectsAt).toBeGreaterThan(manifestAt);
    expect(notFoundAt).toBeGreaterThan(cfasyncAt);
    expect(notFoundAt).toBeGreaterThan(cspAt);
    expect(headersAt).toBeGreaterThan(cspAt);
    expect(validateAt).toBeGreaterThan(
      Math.max(redirectsAt, notFoundAt, headersAt),
    );
    expect(source.slice(validateAt)).not.toMatch(/\b(?:writeFile|copyFile|cp)\(/);
  });

  it("fails the build when _redirects cannot be generated or the dist breaks the contract", async () => {
    const source = await readFile(
      resolve(dashboardRoot, "scripts/build-demo.mjs"),
      "utf8",
    );
    // Logging the problem and carrying on would deploy the broken dist, so
    // both failure paths must end the process with a non-zero status.
    expect(source).toMatch(
      /cannot generate _redirects: \$\{err\.message\}`\);\s*process\.exit\(1\);\s*\}/,
    );
    const validateAt = source.indexOf(
      "await validateDemoPagesDist(distDemoPath, { csp })",
    );
    expect(validateAt).toBeGreaterThan(-1);
    expect(source.slice(validateAt)).toMatch(
      /if \(pagesViolations\.length > 0\) \{[\s\S]*?process\.exit\(1\);\r?\n\}/,
    );
  });
});
