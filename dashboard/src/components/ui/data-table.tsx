/**
 * Enterprise data table built on TanStack Table.
 *
 * Shares rendering, sorting controls and request states with the compound
 * Table primitives. Bulk actions occupy the same control area as filters
 * and wrap on small screens. Selection is scoped to stable entity IDs.
 */
import { Button } from "@/components/ui/button";
import { PaginationControls } from "@/components/ui/pagination-controls";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
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
import { compareTableValues, type TableSortValue } from "@/lib/table-sorting";
import { cn } from "@/lib/utils";
import {
  columnSizingFeature,
  columnVisibilityFeature,
  createSortedRowModel,
  flexRender,
  rowSelectionFeature,
  rowSortingFeature,
  sortFn_alphanumeric,
  sortFn_datetime,
  sortFn_text,
  tableFeatures,
  useTable,
  type ColumnDef,
  type RowData,
  type RowSelectionState,
  type SortingState,
} from "@tanstack/react-table";
import { Columns3 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

export interface BulkActionContext<TData> {
  selectedRows: TData[];
  selectedCount: number;
  allPagesSelected: boolean;
  clearSelection: () => void;
  selectAllPages: () => void;
  selectPageOnly: () => void;
  showSelectAllPages: boolean;
}

export const dataTableFeatures = tableFeatures({
  columnSizingFeature,
  columnVisibilityFeature,
  rowSelectionFeature,
  rowSortingFeature,
  sortFns: {
    alphanumeric: sortFn_alphanumeric,
    datetime: sortFn_datetime,
    text: sortFn_text,
  },
  sortedRowModel: createSortedRowModel(),
});

export type DataTableColumnDef<TData extends RowData> = ColumnDef<
  typeof dataTableFeatures,
  TData,
  unknown
>;

interface DataTableBaseProps<TData extends RowData> {
  columns: DataTableColumnDef<TData>[];
  data: TData[];
  enableSorting?: boolean;
  isLoading?: boolean;
  isFetching?: boolean;
  error?: string | null;
  onRetry?: () => void;
  emptyState?: React.ReactNode;
  /** Cursor APIs return bounded windows. Sorting never silently fetches history. */
  sortingScope?: "all" | "page";
  searchScope?: "all" | "page";
  notice?: React.ReactNode;
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
  /**
   * Columns hidden until the reader asks for them, keyed by column id. A
   * wide table should open on the handful of columns that answer the page's
   * question and keep the rest one click away, not spill past the viewport.
   */
  initialColumnVisibility?: Record<string, boolean>;
  /** Show a "Columns" chooser in the footer so hidden columns are reachable. */
  enableColumnChooser?: boolean;
}

type DataTableSelectionProps<TData extends RowData> =
  | {
      enableSelection: true;
      /** Stable entity identity. Positional row ids are unsafe for bulk actions. */
      getRowId: (row: TData) => string;
      /**
       * Identity of the exact selection scope (project + filters + page).
       * Changing it resets the controlled selection state before another
       * destructive action can observe stale intent.
       */
      selectionScopeKey: string;
    }
  | {
      enableSelection?: false;
      getRowId?: (row: TData) => string;
      selectionScopeKey?: string;
    };

type DataTableProps<TData extends RowData> = DataTableBaseProps<TData> &
  DataTableSelectionProps<TData>;

/**
 * Keep non-selectable tables source-compatible while making stable identity
 * mandatory for every selectable table. Scope changes reset selection without
 * remounting the search controls, so typing never loses focus.
 */
export function DataTable<TData extends RowData>(props: DataTableProps<TData>) {
  const [sorting, setSorting] = useState<SortingState>([]);
  // Sorting and column choices persist independently of selection scope.
  const [columnVisibility, setColumnVisibility] = useState<
    Record<string, boolean>
  >(() => props.initialColumnVisibility ?? {});

  if (
    props.enableSelection &&
    (typeof props.getRowId !== "function" || !props.selectionScopeKey)
  ) {
    throw new Error(
      "Selectable DataTable requires getRowId and a non-empty selectionScopeKey",
    );
  }

  return (
    <DataTableInner
      {...props}
      data={props.error || props.isLoading ? [] : props.data}
      sorting={sorting}
      setSorting={setSorting}
      columnVisibility={columnVisibility}
      setColumnVisibility={setColumnVisibility}
    />
  );
}

function DataTableInner<TData extends RowData>({
  columns,
  data,
  enableSelection = false,
  selectionScopeKey,
  getRowId,
  enableSorting = true,
  isLoading = false,
  isFetching = false,
  error,
  onRetry,
  emptyState,
  sortingScope = "all",
  searchScope = "all",
  notice,
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
  enableColumnChooser = false,
  sorting,
  setSorting,
  columnVisibility,
  setColumnVisibility,
}: DataTableProps<TData> & {
  sorting: SortingState;
  setSorting: React.Dispatch<React.SetStateAction<SortingState>>;
  columnVisibility: Record<string, boolean>;
  setColumnVisibility: React.Dispatch<
    React.SetStateAction<Record<string, boolean>>
  >;
}) {
  const [storedRowSelection, setStoredRowSelection] =
    useState<RowSelectionState>({});
  const [allPagesSelected, setAllPagesSelected] = useState(false);
  const selectionResetKey = JSON.stringify([
    enableSelection,
    selectionScopeKey,
    Boolean(isLoading || error),
  ]);
  const [previousSelectionKey, setPreviousSelectionKey] =
    useState(selectionResetKey);
  // React retries this component before committing descendants. Resetting
  // during render keeps stale bulk intent out of the DOM; unlike keying the
  // entire table, it preserves search focus and other control identities.
  if (previousSelectionKey !== selectionResetKey) {
    setPreviousSelectionKey(selectionResetKey);
    setStoredRowSelection({});
    setAllPagesSelected(false);
  }

  const rowById = useMemo(() => {
    const rows = new Map<string, TData>();
    if (!enableSelection) return rows;
    if (!getRowId) {
      throw new Error("Selectable DataTable has no stable row-id resolver");
    }
    for (const row of data) {
      const id = getRowId(row);
      if (typeof id !== "string" || id.length === 0) {
        throw new Error(
          "Selectable DataTable row ids must be non-empty strings",
        );
      }
      if (rows.has(id)) {
        throw new Error(
          `Selectable DataTable contains duplicate row id: ${id}`,
        );
      }
      rows.set(id, row);
    }
    return rows;
  }, [data, enableSelection, getRowId]);

  // Reconcile retained intent against the current entities, not their array
  // positions. Reordering preserves selection; a removed entity disappears
  // from the effective state immediately and is pruned from retained state.
  const rowSelection = useMemo<RowSelectionState>(() => {
    if (!enableSelection) return {};
    return Object.fromEntries(
      Object.entries(storedRowSelection).filter(
        ([id, selected]) => selected && rowById.has(id),
      ),
    );
  }, [enableSelection, rowById, storedRowSelection]);
  const storedSelectionKey = JSON.stringify(
    Object.keys(storedRowSelection)
      .filter((id) => storedRowSelection[id])
      .sort(),
  );
  const reconciledSelectionKey = JSON.stringify(
    Object.keys(rowSelection).sort(),
  );

  useEffect(() => {
    if (!enableSelection || storedSelectionKey === reconciledSelectionKey) {
      return;
    }
    setStoredRowSelection(rowSelection);
  }, [
    enableSelection,
    reconciledSelectionKey,
    rowSelection,
    storedSelectionKey,
  ]);

  const allColumns: DataTableColumnDef<TData>[] = enableSelection
    ? [selectionColumn<TData>(), ...columns]
    : columns;

  const table = useTable({
    features: dataTableFeatures,
    data,
    columns: allColumns,
    defaultColumn: {
      sortDescFirst: false,
      sortUndefined: "last",
      sortFn: (a, b, id) => {
        const left = a.getValue(id) as TableSortValue;
        const right = b.getValue(id) as TableSortValue;
        const missing = (v: TableSortValue) =>
          v == null || (typeof v === "number" && !Number.isFinite(v));
        // TanStack reverses comparator results for descending. Compensate
        // only for missing values so they stay last in either direction.
        const missingPair = missing(left) !== missing(right);
        const descending = a.table.getColumn(id)?.getIsSorted() === "desc";
        return (
          compareTableValues(left, right) * (missingPair && descending ? -1 : 1)
        );
      },
    },
    state: { sorting, rowSelection, columnVisibility },
    onColumnVisibilityChange: (updater) =>
      setColumnVisibility((prev) =>
        typeof updater === "function" ? updater(prev) : updater,
      ),
    onSortingChange: setSorting,
    onRowSelectionChange: (updater) => {
      const next =
        typeof updater === "function" ? updater(rowSelection) : updater;
      setStoredRowSelection(
        Object.fromEntries(
          Object.entries(next).filter(
            ([id, selected]) => selected && rowById.has(id),
          ),
        ),
      );
      // A checkbox change while "all pages" is active narrows the intent back
      // to an explicit stable-id selection; it must not silently retain the
      // broader destructive scope.
      setAllPagesSelected(false);
    },
    getRowId,
    enableSorting,
    enableRowSelection: enableSelection,
    // V9 enables inclusive Shift-range selection by default. This component
    // intentionally preserves the V8 checkbox semantics: each click changes
    // only the addressed stable row id.
    enableRowRangeSelection: false,
  });

  const explicitSelectedRows = useMemo(
    () =>
      Object.keys(rowSelection)
        .filter((id) => rowSelection[id])
        .map((id) => rowById.get(id))
        .filter((row): row is TData => row !== undefined),
    [rowById, rowSelection],
  );
  const selectedRows = useMemo(
    () => (allPagesSelected ? data : explicitSelectedRows),
    [allPagesSelected, data, explicitSelectedRows],
  );
  const onSelectionChangeRef = useRef(onSelectionChange);
  const selectedRowsRef = useRef(selectedRows);
  const lastNotifiedSelectionKeyRef = useRef<string | undefined>(undefined);
  const selectionNotificationKey = allPagesSelected
    ? `all:${JSON.stringify([...rowById.keys()].sort())}`
    : `explicit:${reconciledSelectionKey}`;

  // Keep the latest render values for the semantic notification below. This
  // ref-only effect may run for new callback/array identities, but cannot feed
  // a parent render loop; the following effect is keyed only by selected IDs.
  useEffect(() => {
    onSelectionChangeRef.current = onSelectionChange;
    selectedRowsRef.current = selectedRows;
  }, [onSelectionChange, selectedRows]);

  useEffect(() => {
    if (
      !enableSelection ||
      lastNotifiedSelectionKeyRef.current === selectionNotificationKey
    ) {
      return;
    }
    lastNotifiedSelectionKeyRef.current = selectionNotificationKey;
    onSelectionChangeRef.current?.(selectedRowsRef.current);
  }, [enableSelection, selectionNotificationKey]);

  const rawSelectedCount = explicitSelectedRows.length;
  const selectedCount = allPagesSelected
    ? (totalCount ?? data.length)
    : rawSelectedCount;

  const clearSelection = () => {
    setStoredRowSelection({});
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
    <div data-slot="data-table" className="space-y-4" aria-busy={isLoading}>
      {toolbar && (
        <div data-slot="collection-controls" className="min-h-9">
          {toolbar(bulkCtx)}
        </div>
      )}
      {notice}

      {/* Table */}
      {/* overflow-x-auto, not hidden: a table wider than the viewport must
          scroll, not silently lose its rightmost columns. The schedules table
          lost Last run, Next run, Enabled and its actions at 1440px this way. */}
      <div className="panel-surface overflow-hidden">
        <Table
          isLoading={isLoading}
          error={error}
          onRetry={onRetry}
          emptyState={emptyState}
        >
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id}>
                {hg.headers.map((header) => (
                  <TableHead
                    key={header.id}
                    sortDirection={header.column.getIsSorted()}
                    onSort={
                      header.column.getCanSort()
                        ? () => header.column.toggleSorting()
                        : undefined
                    }
                  >
                    {header.isPlaceholder
                      ? null
                      : flexRender(
                          header.column.columnDef.header,
                          header.getContext(),
                        )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows.map((row) => (
              <TableRow
                key={row.id}
                data-state={row.getIsSelected() && "selected"}
                className={cn(row.getIsSelected() && "bg-primary/5")}
              >
                {row.getVisibleCells().map((cell) => (
                  <TableCell key={cell.id}>
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Pagination footer */}
      <div
        data-slot="table-pagination"
        className="flex min-h-9 flex-wrap items-center justify-between gap-3 text-sm"
      >
        <div className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-2 text-sm text-muted-foreground">
          {totalLabel && (
            <span role="status">
              {isLoading
                ? "Loading records…"
                : error
                  ? "Records unavailable"
                  : totalLabel}
            </span>
          )}
          {(sortingScope === "page" || onNextPage) && (
            <span className="text-xs text-muted-foreground">
              {searchScope === "page"
                ? "Search and sorting apply to this page"
                : "Sorting applies to this page"}
            </span>
          )}
          {enableColumnChooser && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm">
                  <Columns3 className="size-3.5" />
                  Columns
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="w-48">
                <DropdownMenuLabel>Show columns</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {table
                  .getAllLeafColumns()
                  .filter((c) => c.getCanHide() && c.id !== "select")
                  .map((c) => {
                    const header = c.columnDef.header;
                    const label =
                      typeof header === "string" && header.length > 0
                        ? header
                        : c.id;
                    return (
                      <DropdownMenuCheckboxItem
                        key={c.id}
                        checked={c.getIsVisible()}
                        onCheckedChange={(v) => c.toggleVisibility(!!v)}
                        onSelect={(e) => e.preventDefault()}
                      >
                        {label}
                      </DropdownMenuCheckboxItem>
                    );
                  })}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>

        <div className="flex items-center gap-4">
          {onPageSizeChange && (
            <div className="flex items-center gap-2 text-sm">
              <span className="text-muted-foreground">Rows per page</span>
              <Select
                value={String(pageSize)}
                onValueChange={(v) => onPageSizeChange(parseInt(v, 10))}
              >
                <SelectTrigger aria-label="Rows per page" className="w-20">
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

          <PaginationControls
            hasPreviousPage={hasPreviousPage}
            hasNextPage={hasNextPage}
            onFirstPage={onFirstPage}
            onPreviousPage={onPreviousPage}
            onNextPage={onNextPage}
            pending={isLoading || isFetching}
          />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Selection column
// ---------------------------------------------------------------------------

function selectionColumn<TData extends RowData>(): DataTableColumnDef<TData> {
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
