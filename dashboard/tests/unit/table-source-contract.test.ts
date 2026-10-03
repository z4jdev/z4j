import { readdirSync, readFileSync } from "node:fs";
import { resolve, join, sep } from "node:path";
import ts from "typescript";
import { expect, it } from "vitest";

// Paths are compared as POSIX strings so the "/components/ui/" and
// "_authenticated" checks below hold on Windows checkouts, where
// node:path joins with backslashes, as well as on Linux CI.
function posix(path: string): string {
  return path.split(sep).join("/");
}

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? files(join(dir, entry.name))
      : entry.name.endsWith(".tsx")
        ? [posix(join(dir, entry.name))]
        : [],
  );
}

it("every record column declares sorting; only action or decorative headers omit it", () => {
  const violations: string[] = [];
  const root = posix(resolve("src"));
  for (const file of files(root).filter(
    (file) => !file.includes("/components/ui/"),
  )) {
    const source = readFileSync(file, "utf8");
    const ast = ts.createSourceFile(
      file,
      source,
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TSX,
    );
    function visit(node: ts.Node) {
      if (
        ts.isJsxElement(node) &&
        node.openingElement.tagName.getText(ast) === "TableHead"
      ) {
        const label = node.children
          .map((child) => child.getText(ast))
          .join("")
          .trim();
        const sortable = node.openingElement.attributes.properties.some(
          (attr) =>
            ts.isJsxAttribute(attr) && attr.name.getText(ast) === "sortKey",
        );
        if (!sortable && label && !["Actions", "Manage"].includes(label))
          violations.push(`${file.slice(root.length + 1)}: ${label}`);
      }
      if (
        (ts.isJsxElement(node) &&
          node.openingElement.tagName.getText(ast) === "table") ||
        (ts.isJsxSelfClosingElement(node) &&
          node.tagName.getText(ast) === "table")
      )
        violations.push(`${file}: raw table bypasses shared primitives`);
      ts.forEachChild(node, visit);
    }
    visit(ast);
  }
  expect(violations).toEqual([]);
});

it("all authenticated page titles use the shared PageHeader", () => {
  const violations = files(resolve("src/routes"))
    .filter((file) => file.includes("_authenticated"))
    .filter((file) => /<h1[\s>]/.test(readFileSync(file, "utf8")));
  expect(violations).toEqual([]);
});
