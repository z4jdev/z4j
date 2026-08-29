/**
 * Column visibility: a chosen default set, a chooser that reveals more, and
 * choices that survive the keyed inner table remounting on a filter change.
 */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DataTable, type DataTableColumnDef } from "@/components/ui/data-table";

interface Row {
  id: string;
  label: string;
  extra: string;
}
const columns: DataTableColumnDef<Row>[] = [
  { accessorKey: "label", header: "Label", enableHiding: false },
  { accessorKey: "extra", header: "Extra" },
];
const rows: Row[] = [{ id: "1", label: "one", extra: "more" }];

function Table({ scope }: { scope: string }) {
  return (
    <DataTable
      columns={columns}
      data={rows}
      enableSelection
      getRowId={(r) => r.id}
      selectionScopeKey={scope}
      initialColumnVisibility={{ extra: false }}
      enableColumnChooser
    />
  );
}

const headers = (root: HTMLElement) =>
  Array.from(root.querySelectorAll("th")).map((h) => h.textContent?.trim() ?? "");

describe("DataTable column visibility", () => {
  it("opens on the chosen columns, scrolls instead of clipping, and offers a chooser", () => {
    const { container } = render(<Table scope="a" />);
    expect(headers(container)).toContain("Label");
    expect(headers(container)).not.toContain("Extra");
    expect(container.querySelector(".overflow-x-auto")).not.toBeNull();
    expect(screen.getByRole("button", { name: /Columns/ })).toBeInTheDocument();
  });

  it("keeps a revealed column across a filter change that remounts the inner table", async () => {
    const view = render(<Table scope="a" />);
    const trigger = screen.getByRole("button", { name: /Columns/ });
    fireEvent.keyDown(trigger, { key: "Enter" });
    const item = await screen.findByRole("menuitemcheckbox", { name: "Extra" });
    fireEvent.click(item);
    await waitFor(() => expect(headers(view.container)).toContain("Extra"));
    // A new selection scope remounts DataTableInner; the choice must survive.
    view.rerender(<Table scope="b" />);
    await waitFor(() => expect(headers(view.container)).toContain("Extra"));
  });

  it("never offers the identity column for hiding", async () => {
    render(<Table scope="a" />);
    fireEvent.keyDown(screen.getByRole("button", { name: /Columns/ }), { key: "Enter" });
    await screen.findByRole("menuitemcheckbox", { name: "Extra" });
    expect(screen.queryByRole("menuitemcheckbox", { name: "Label" })).toBeNull();
  });
});
