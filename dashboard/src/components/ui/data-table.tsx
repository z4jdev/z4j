/**
 * Enterprise data table built on TanStack Table.
 *
 * Layout-shift-free design: the toolbar strip between filters and
 * the table has a fixed height. When rows are selected the bulk
 * action bar replaces the toolbar IN-PLACE - the table rows never
 * move. This follows the Shopify admin pattern used by enterprise
 * dashboards where power users rely on muscle memory.
 */
import { useState } from "react";
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

export interface BulkActionContext<TData> {
  selectedRows: TData[];
  selectedCount: number;
  allPagesSelected: boolean;
  clearSelection: () => void;
  selectAllPages: () => void;
  selectPageOnly: () => void;
  showSelectAllPages: boolean;
}

interface DataTableProps<TData> {
  columns: ColumnDef<TData, unknown>[];
  data: TData[];
  enableSelection?: boolean;
  enableSorting?: boolean;
  pageSize?: number;
  pageSizeOptions?: number[];
  onPageSizeChange?: (size: number) => void;
  hasNextPage?: boolean;
  hasPreviousPage?: boolean;
  onNextPage?: () => void;
  onPreviousPage?: () => void;
  onFirstPage?: () => void;
  totalLabel?: string;
  onSelectionChange?: (rows: TData[]) => void;
  totalCount?: number;
  /**
   * Render the toolbar strip above the table. Receives the bulk
   * action context so the caller can swap between filter UI and
   * bulk action UI without layout shift.
   */
  toolbar?: (ctx: BulkActionContext<TData>) => React.ReactNode;
}

export function DataTable<TData>({
  columns,
  data,
  enableSelection = false,
  enableSorting = true,
  pageSize = 50,
  pageSizeOptions = [10, 25, 50, 100],
  onPageSizeChange,
  hasNextPage = false,
  hasPreviousPage = false,
  onNextPage,
  onPreviousPage,
  onFirstPage,
  totalLabel,
  onSelectionChange,
  totalCount,
  toolbar,
}: DataTableProps<TData>) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [rowSelection, setRowSelection] = useState<Record<string, boolean>>({});
  const [allPagesSelected, setAllPagesSelected] = useState(false);

  const allColumns: ColumnDef<TData, unknown>[] = enableSelection
    ? [selectionColumn<TData>(), ...columns]
    : columns;

  const table = useReactTable({
    data,
    columns: allColumns,
    state: { sorting, rowSelection },
    onSortingChange: setSorting,
    onRowSelectionChange: (updater) => {
      const next =
        typeof updater === "function" ? updater(rowSelection) : updater;
      setRowSelection(next);
      if (onSelectionChange) {
        const selectedRows = Object.keys(next)
          .filter((k) => next[k])
          .map((k) => data[parseInt(k, 10)])
          .filter(Boolean);
        onSelectionChange(selectedRows);
      }
    },
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: enableSorting ? getSortedRowModel() : undefined,
    enableRowSelection: enableSelection,
  });

  const rawSelectedCount = Object.values(rowSelection).filter(Boolean).length;
  const selectedCount = allPagesSelected
    ? (totalCount ?? data.length)
    : rawSelectedCount;
  const selectedRows = allPagesSelected
    ? data
    : Object.keys(rowSelection)
        .filter((k) => rowSelection[k])
        .map((k) => data[parseInt(k, 10)])
        .filter(Boolean);

  const clearSelection = () => {
    setRowSelection({});
    setAllPagesSelected(false);
  };

  const allPageRowsSelected =
    data.length > 0 && rawSelectedCount === data.length;
  const showSelectAllPages =
    allPageRowsSelected &&
    !allPagesSelected &&
    (hasNextPage || (totalCount !== undefined && totalCount > data.length));

  const bulkCtx: BulkActionContext<TData> = {
    selectedRows,
    selectedCount,
    allPagesSelected,
    clearSelection,
    selectAllPages: () => setAllPagesSelected(true),
    selectPageOnly: () => setAllPagesSelected(false),
    showSelectAllPages,
  };

  return (
    <div className="space-y-0">
      {/* Toolbar strip - fixed height, never causes layout shift.
          Both filter bar and bulk action bar render inside this
          same-height box so the table Y position is stable. */}
      {toolbar && (
        <div className="flex h-[52px] items-center">
          <div className="w-full">{toolbar(bulkCtx)}</div>
        </div>
      )}

      {/* Table */}
      <div className="mt-2 overflow-hidden rounded-lg border bg-card">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id}>
                {hg.headers.map((header) => (
                  <TableHead
                    key={header.id}
                    className={cn(
                      header.column.getCanSort() &&
                        "cursor-pointer select-none",
                    )}
                    onClick={header.column.getToggleSortingHandler()}
                  >
                    <div className="flex items-center gap-1">
                      {header.isPlaceholder
                        ? null
                        : flexRender(
                            header.column.columnDef.header,
                            header.getContext(),
                          )}
                      {header.column.getCanSort() && (
                        <SortIcon sorted={header.column.getIsSorted()} />
                      )}
                    </div>
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={allColumns.length}
                  className="h-24 text-center text-muted-foreground"
                >
                  No results.
                </TableCell>
              </TableRow>
            ) : (
              table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  data-state={row.getIsSelected() && "selected"}
                  className={cn(
                    row.getIsSelected() && "bg-primary/5",
                  )}
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext(),
                      )}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination footer */}
      <div className="flex items-center justify-between px-1 pt-3">
        <div className="flex items-center gap-4 text-sm text-muted-foreground">
          {totalLabel && <span>{totalLabel}</span>}
        </div>

        <div className="flex items-center gap-4">
          {onPageSizeChange && (
            <div className="flex items-center gap-2 text-sm">
              <span className="text-muted-foreground">Rows per page</span>
              <Select
                value={String(pageSize)}
                onValueChange={(v) => onPageSizeChange(parseInt(v, 10))}
              >
                <SelectTrigger className="h-8 w-[70px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {pageSizeOptions.map((size) => (
                    <SelectItem key={size} value={String(size)}>
                      {size}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          <div className="flex items-center gap-1">
            {onFirstPage && (
              <Button
                variant="outline"
                size="icon"
                className="size-8"
                disabled={!hasPreviousPage}
                onClick={onFirstPage}
                aria-label="Go to first page"
              >
                <ChevronsLeft className="size-4" />
              </Button>
            )}
            {onPreviousPage && (
              <Button
                variant="outline"
                size="icon"
                className="size-8"
                disabled={!hasPreviousPage}
                onClick={onPreviousPage}
                aria-label="Go to previous page"
              >
                <ChevronLeft className="size-4" />
              </Button>
            )}
            {onNextPage && (
              <Button
                variant="outline"
                size="icon"
                className="size-8"
                disabled={!hasNextPage}
                onClick={onNextPage}
                aria-label="Go to next page"
              >
                <ChevronRight className="size-4" />
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Selection column
// ---------------------------------------------------------------------------

function selectionColumn<TData>(): ColumnDef<TData, unknown> {
  return {
    id: "select",
    header: ({ table }) => (
      <Checkbox
        checked={
          table.getIsAllPageRowsSelected() ||
          (table.getIsSomePageRowsSelected() && "indeterminate")
        }
        onCheckedChange={(v) => table.toggleAllPageRowsSelected(!!v)}
        aria-label="Select all"
      />
    ),
    cell: ({ row }) => (
      <Checkbox
        checked={row.getIsSelected()}
        onCheckedChange={(v) => row.toggleSelected(!!v)}
        aria-label="Select row"
      />
    ),
    enableSorting: false,
    enableHiding: false,
    size: 40,
  };
}

// ---------------------------------------------------------------------------
// Sort icon
// ---------------------------------------------------------------------------

function SortIcon({ sorted }: { sorted: false | "asc" | "desc" }) {
  if (sorted === "asc") return <ArrowUp className="size-3.5" />;
  if (sorted === "desc") return <ArrowDown className="size-3.5" />;
  return <ArrowUpDown className="size-3.5 opacity-30" />;
}
