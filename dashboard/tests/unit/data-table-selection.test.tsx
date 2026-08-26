import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import {
  DataTable,
  type BulkActionContext,
  type DataTableColumnDef,
} from "@/components/ui/data-table";

interface Row {
  id: string;
  label: string;
}

const columns: DataTableColumnDef<Row>[] = [
  { accessorKey: "label", header: "Label" },
];
const rowId = (row: Row) => row.id;

function toolbar(onAction: (rows: Row[]) => void, ctx: BulkActionContext<Row>) {
  return (
    <div>
      <output data-testid="selected-ids">
        {ctx.selectedRows.map((row) => row.id).join(",")}
      </output>
      <output data-testid="all-pages">{String(ctx.allPagesSelected)}</output>
      <button type="button" onClick={() => onAction(ctx.selectedRows)}>
        Act
      </button>
      <button type="button" onClick={ctx.selectAllPages}>
        Select every page
      </button>
    </div>
  );
}

describe("DataTable stable destructive selection", () => {
  it("settles with an inline state-writing callback and recreated equivalent data", async () => {
    function InlineParent() {
      const [notificationCount, setNotificationCount] = useState(0);
      const recreatedRows = [
        { id: "a", label: "A" },
        { id: "b", label: "B" },
      ];
      return (
        <>
          <output data-testid="notification-count">{notificationCount}</output>
          <DataTable
            columns={columns}
            data={recreatedRows}
            enableSelection
            getRowId={rowId}
            selectionScopeKey="project:inline:page-1"
            onSelectionChange={() => setNotificationCount((count) => count + 1)}
          />
        </>
      );
    }

    render(<InlineParent />);
    await waitFor(() =>
      expect(screen.getByTestId("notification-count")).toHaveTextContent("1"),
    );

    fireEvent.click(screen.getAllByRole("checkbox", { name: "Select row" })[0]);
    await waitFor(() =>
      expect(screen.getByTestId("notification-count")).toHaveTextContent("2"),
    );
  });

  it("preserves the selected entity through a same-scope row reorder", () => {
    const action = vi.fn();
    const { rerender } = render(
      <DataTable
        columns={columns}
        data={[
          { id: "a", label: "A" },
          { id: "b", label: "B" },
        ]}
        enableSelection
        getRowId={rowId}
        selectionScopeKey="project:scope:page-1"
        toolbar={(ctx) => toolbar(action, ctx)}
      />,
    );

    fireEvent.click(screen.getAllByRole("checkbox", { name: "Select row" })[0]);
    expect(screen.getByTestId("selected-ids")).toHaveTextContent("a");

    rerender(
      <DataTable
        columns={columns}
        data={[
          { id: "new", label: "New" },
          { id: "a", label: "A updated" },
          { id: "b", label: "B" },
        ]}
        enableSelection
        getRowId={rowId}
        selectionScopeKey="project:scope:page-1"
        toolbar={(ctx) => toolbar(action, ctx)}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Act" }));

    expect(action).toHaveBeenCalledWith([{ id: "a", label: "A updated" }]);
  });

  it("prunes a selected id that disappears without retargeting its index", async () => {
    const selectionChanged = vi.fn();
    const { rerender } = render(
      <DataTable
        columns={columns}
        data={[
          { id: "a", label: "A" },
          { id: "b", label: "B" },
        ]}
        enableSelection
        getRowId={rowId}
        selectionScopeKey="project:scope:page-1"
        onSelectionChange={selectionChanged}
        toolbar={(ctx) => toolbar(vi.fn(), ctx)}
      />,
    );
    fireEvent.click(screen.getAllByRole("checkbox", { name: "Select row" })[0]);

    rerender(
      <DataTable
        columns={columns}
        data={[{ id: "b", label: "B" }]}
        enableSelection
        getRowId={rowId}
        selectionScopeKey="project:scope:page-1"
        onSelectionChange={selectionChanged}
        toolbar={(ctx) => toolbar(vi.fn(), ctx)}
      />,
    );

    expect(screen.getByTestId("selected-ids")).toBeEmptyDOMElement();
    await waitFor(() => expect(selectionChanged).toHaveBeenLastCalledWith([]));
    expect(
      screen.getByRole("checkbox", { name: "Select row" }),
    ).not.toBeChecked();
  });

  it("clears explicit and all-pages intent when the selection scope changes", () => {
    const action = vi.fn();
    const rows = [
      { id: "a", label: "A" },
      { id: "b", label: "B" },
    ];
    const { rerender } = render(
      <DataTable
        columns={columns}
        data={rows}
        enableSelection
        getRowId={rowId}
        selectionScopeKey="project:failure:page-1"
        toolbar={(ctx) => toolbar(action, ctx)}
      />,
    );
    fireEvent.click(screen.getAllByRole("checkbox", { name: "Select row" })[0]);
    fireEvent.click(screen.getByRole("button", { name: "Select every page" }));
    expect(screen.getByTestId("all-pages")).toHaveTextContent("true");

    rerender(
      <DataTable
        columns={columns}
        data={rows}
        enableSelection
        getRowId={rowId}
        selectionScopeKey="project:success:page-1"
        toolbar={(ctx) => toolbar(action, ctx)}
      />,
    );

    expect(screen.getByTestId("selected-ids")).toBeEmptyDOMElement();
    expect(screen.getByTestId("all-pages")).toHaveTextContent("false");
    fireEvent.click(screen.getByRole("button", { name: "Act" }));
    expect(action).toHaveBeenLastCalledWith([]);
  });
});
