import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { DataTable, type DataTableColumnDef } from "@/components/ui/data-table";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { FilterToolbar } from "@/components/domain/filter-toolbar";
import { sortTimestamp } from "@/lib/table-sorting";

type RecordRow = {
  id: string;
  name: string;
  count: number | null;
  date: string | null;
};
const records: RecordRow[] = [
  { id: "ten", name: "queue10", count: 10, date: "2026-09-08T12:00:00Z" },
  { id: "missing", name: "queue3", count: null, date: null },
  { id: "two", name: "queue2", count: 2, date: "2026-09-08T13:00:00+02:00" },
];
const columns: DataTableColumnDef<RecordRow>[] = [
  { accessorKey: "name", header: "Name" },
  { accessorKey: "count", header: "Count" },
  {
    id: "date",
    accessorFn: (row) => sortTimestamp(row.date),
    header: "Date",
    cell: ({ row }) => row.original.date ?? "Never",
  },
];
function Compound({
  data = records,
  loading = false,
  error = false,
  retry = () => {},
}: {
  data?: RecordRow[];
  loading?: boolean;
  error?: boolean;
  retry?: () => void;
}) {
  return (
    <Table
      searchable
      isLoading={loading}
      error={error ? "Could not load records" : null}
      onRetry={retry}
    >
      <TableHeader>
        <TableRow>
          <TableHead sortKey="name">Name</TableHead>
          <TableHead sortKey="count">Count</TableHead>
          <TableHead sortKey="date">Date</TableHead>
          <TableHead>Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.map((row) => (
          <TableRow
            key={row.id}
            sortValues={{
              name: row.name,
              count: row.count,
              date: sortTimestamp(row.date),
            }}
          >
            <TableCell>{row.name}</TableCell>
            <TableCell>{row.count}</TableCell>
            <TableCell>{row.date ?? "Never"}</TableCell>
            <TableCell>
              <input aria-label={`Note ${row.name}`} />
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
const names = () =>
  Array.from(document.querySelectorAll("tbody tr")).map(
    (row) => row.querySelector("td")?.textContent,
  );

describe.each(["compound", "data"] as const)("%s table contract", (kind) => {
  function mount(data = records) {
    return render(
      kind === "compound" ? (
        <Compound data={data} />
      ) : (
        <DataTable columns={columns} data={data} getRowId={(row) => row.id} />
      ),
    );
  }
  it("sorts numbers numerically, leaves missing values last in both directions, and clears to source order", () => {
    mount();
    const header = screen.getByRole("columnheader", { name: "Count" });
    const button = within(header).getByRole("button", { name: "Count" });
    fireEvent.click(button);
    expect(header).toHaveAttribute("aria-sort", "ascending");
    expect(names()).toEqual(["queue2", "queue10", "queue3"]);
    fireEvent.click(button);
    expect(header).toHaveAttribute("aria-sort", "descending");
    expect(names()).toEqual(["queue10", "queue2", "queue3"]);
    fireEvent.click(button);
    expect(header).toHaveAttribute("aria-sort", "none");
    expect(names()).toEqual(["queue10", "queue3", "queue2"]);
  });
  it("sorts timestamps by instant, with missing dates last", () => {
    mount();
    fireEvent.click(screen.getByRole("button", { name: "Date", exact: true }));
    expect(names()).toEqual(["queue2", "queue10", "queue3"]);
  });
  it("supports natural text ordering and keyboard activation", async () => {
    mount();
    const button = screen.getByRole("button", { name: "Name", exact: true });
    button.focus();
    await userEvent.keyboard("{Enter}");
    expect(names()).toEqual(["queue2", "queue3", "queue10"]);
    await userEvent.keyboard(" ");
    expect(names()).toEqual(["queue10", "queue3", "queue2"]);
  });
});

it("retains stable record identity through sorting, filtering, and new data", () => {
  const view = render(<Compound />);
  fireEvent.change(screen.getByRole("textbox", { name: "Note queue10" }), {
    target: { value: "keep me" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Count" }));
  expect(screen.getByRole("textbox", { name: "Note queue10" })).toHaveValue(
    "keep me",
  );
  fireEvent.change(screen.getByRole("searchbox"), {
    target: { value: "queue10" },
  });
  expect(names()).toEqual(["queue10"]);
  expect(screen.getByRole("textbox", { name: "Note queue10" })).toHaveValue(
    "keep me",
  );
  view.rerender(<Compound data={[{ ...records[0], count: 1 }]} />);
  expect(screen.getByRole("textbox", { name: "Note queue10" })).toHaveValue(
    "keep me",
  );
});

it("keeps controls and headers through loading, empty, and error states, with retry", () => {
  const retry = vi.fn();
  const view = render(<Compound loading data={[]} />);
  const input = screen.getByRole("searchbox");
  expect(screen.getAllByRole("columnheader")).toHaveLength(4);
  view.rerender(<Compound data={[]} />);
  expect(screen.getByRole("searchbox")).toBe(input);
  expect(screen.getByText("No results match your filters.")).toBeVisible();
  view.rerender(<Compound data={[]} error retry={retry} />);
  expect(screen.getByRole("searchbox")).toBe(input);
  expect(screen.getByRole("alert")).toHaveTextContent("Could not load records");
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  expect(retry).toHaveBeenCalledOnce();
  expect(
    within(screen.getByRole("columnheader", { name: "Actions" })).queryByRole(
      "button",
    ),
  ).toBeNull();
});

it("retains DataTable controls and paging on empty and failed cursor pages", () => {
  const first = vi.fn();
  const props = {
    columns,
    data: [] as RecordRow[],
    toolbar: () => <FilterToolbar searchValue="" onSearchChange={() => {}} />,
    hasPreviousPage: true,
    onFirstPage: first,
    onNextPage: () => {},
    hasNextPage: false,
  };
  const view = render(<DataTable {...props} isLoading />);
  const search = screen.getByRole("searchbox");
  view.rerender(<DataTable {...props} />);
  expect(screen.getByRole("searchbox")).toBe(search);
  expect(
    screen.getByRole("button", { name: "Go to next page" }),
  ).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Go to first page" }));
  expect(first).toHaveBeenCalledOnce();
  view.rerender(<DataTable {...props} error="Page unavailable" />);
  expect(screen.getByRole("alert")).toHaveTextContent("Page unavailable");
  expect(screen.getByText("Sorting applies to this page")).toBeVisible();
});
