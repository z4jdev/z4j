import { EmptyState } from "@/components/domain/empty-state";
import { FilterToolbar } from "@/components/domain/filter-toolbar";
import { QueryError } from "@/components/domain/query-error";
import { Skeleton } from "@/components/ui/skeleton";
import { compareTableValues, type TableSortValue } from "@/lib/table-sorting";
import { cn } from "@/lib/utils";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import * as React from "react";

type SortState = { key: string; direction: "asc" | "desc" } | null;
export type TableRowSortProps = { sortValues?: Record<string, TableSortValue> };
const SortContext = React.createContext<{
  sorting: SortState;
  toggle: (key: string) => void;
  search: string;
  isLoading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  emptyState?: React.ReactNode;
  columnCount: number;
} | null>(null);

function Table({
  className,
  children,
  toolbar,
  notice,
  filters,
  searchable = false,
  searchPlaceholder = "Search records…",
  isLoading,
  error,
  onRetry,
  emptyState,
  footer,
  sortingScope = "all",
  ...props
}: React.HTMLAttributes<HTMLTableElement> & {
  toolbar?: React.ReactNode;
  notice?: React.ReactNode;
  filters?: React.ReactNode;
  searchable?: boolean;
  searchPlaceholder?: string;
  isLoading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  emptyState?: React.ReactNode;
  footer?: React.ReactNode;
  sortingScope?: "all" | "page";
}) {
  const [search, setSearch] = React.useState("");
  const columnCount = countHeaders(children);
  const collection = searchable || toolbar !== undefined;
  const records = collection ? collectRecords(children) : [];
  const query = search.trim().toLocaleLowerCase();
  const matchingCount = records.filter(
    (row) =>
      !query ||
      Object.values(row.props.sortValues ?? {}).some(
        (value) =>
          value != null && String(value).toLocaleLowerCase().includes(query),
      ),
  ).length;
  const [sorting, setSorting] = React.useState<SortState>(null);
  const toggle = React.useCallback(
    (key: string) =>
      setSorting((current) =>
        current?.key !== key
          ? { key, direction: "asc" }
          : current.direction === "asc"
            ? { key, direction: "desc" }
            : null,
      ),
    [],
  );
  return (
    <SortContext.Provider
      value={{
        sorting,
        toggle,
        search,
        isLoading,
        error,
        onRetry,
        emptyState,
        columnCount,
      }}
    >
      <div
        data-slot={collection ? "collection" : undefined}
        className={collection ? "space-y-4" : undefined}
        aria-busy={isLoading}
      >
        {collection && (
          <div data-slot="collection-controls">
            {toolbar ?? (
              <FilterToolbar
                filters={filters}
                searchValue={search}
                onSearchChange={setSearch}
                searchPlaceholder={searchPlaceholder}
                activeFilterCount={search ? 1 : 0}
                onClear={() => setSearch("")}
              />
            )}
          </div>
        )}
        {notice}
        <div
          data-slot="table-container"
          className={cn(
            "relative w-full overflow-x-auto",
            collection && "panel-surface",
          )}
        >
          <table
            data-slot="table"
            className={cn("w-full caption-bottom text-sm", className)}
            {...props}
          >
            {children}
          </table>
        </div>
        {(collection || footer || sortingScope === "page") && (
          <div
            data-slot="table-pagination"
            className="flex min-h-9 flex-wrap items-center justify-between gap-3 text-sm text-muted-foreground"
          >
            {footer ?? (
              <span role="status">
                {isLoading
                  ? "Loading records…"
                  : error
                    ? "Records unavailable"
                    : query
                      ? `${matchingCount} of ${records.length} records`
                      : `${records.length} record${records.length === 1 ? "" : "s"}`}
              </span>
            )}
            {sortingScope === "page" && (
              <span className="text-xs">
                Search and sorting apply to this page
              </span>
            )}
          </div>
        )}
      </div>
    </SortContext.Provider>
  );
}

function collectRecords(
  children: React.ReactNode,
): React.ReactElement<TableRowSortProps>[] {
  const rows: React.ReactElement<TableRowSortProps>[] = [];
  React.Children.forEach(children, (child) => {
    if (
      !React.isValidElement<TableRowSortProps & { children?: React.ReactNode }>(
        child,
      )
    )
      return;
    if (child.props.sortValues) rows.push(child);
    else rows.push(...collectRecords(child.props.children));
  });
  return rows;
}

function countHeaders(children: React.ReactNode): number {
  let count = 0;
  React.Children.forEach(children, (child) => {
    if (!React.isValidElement<{ children?: React.ReactNode }>(child)) return;
    if (child.type === TableHead) count += 1;
    else count += countHeaders(child.props.children);
  });
  return count;
}

function TableHeader({
  className,
  ...props
}: React.HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <thead
      data-slot="table-header"
      className={cn(
        "[&_tr]:h-11 [&_tr]:border-b [&_tr]:bg-muted/50",
        className,
      )}
      {...props}
    />
  );
}

function TableBody({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLTableSectionElement>) {
  const context = React.useContext(SortContext);
  const rows = React.useMemo(() => {
    const keyedChildren = React.Children.toArray(children);
    if (!context?.sorting && !context?.search) return keyedChildren;
    const { key, direction } = context?.sorting ?? {
      key: "",
      direction: "asc" as const,
    };
    // Sort record elements by explicit domain values. Never scrape rendered
    // text: relative dates, formatted counts and badges are presentation only.
    const query = context?.search.toLocaleLowerCase().trim();
    const entries = keyedChildren.filter((child) => {
      if (
        !query ||
        !React.isValidElement<TableRowSortProps>(child) ||
        !child.props.sortValues
      )
        return true;
      return Object.values(child.props.sortValues).some(
        (value) =>
          value != null && String(value).toLocaleLowerCase().includes(query),
      );
    });
    const sortable = entries
      .filter(
        (child): child is React.ReactElement<TableRowSortProps> =>
          React.isValidElement<TableRowSortProps>(child) &&
          child.props.sortValues !== undefined,
      )
      .sort((a, b) =>
        compareTableValues(
          a.props.sortValues?.[key],
          b.props.sortValues?.[key],
          direction,
        ),
      );
    let index = 0;
    return entries.map((child) =>
      React.isValidElement<TableRowSortProps>(child) &&
      child.props.sortValues !== undefined
        ? sortable[index++]
        : child,
    );
  }, [children, context?.sorting, context?.search]);
  return (
    <tbody
      data-slot="table-body"
      className={cn("[&_tr:last-child]:border-0", className)}
      {...props}
    >
      {context?.isLoading ? (
        Array.from({ length: 6 }, (_, index) => (
          <TableRow key={index}>
            <TableCell colSpan={context.columnCount}>
              <Skeleton className="h-6 w-full" />
            </TableCell>
          </TableRow>
        ))
      ) : context?.error ? (
        <TableRow>
          <TableCell colSpan={context.columnCount} className="p-0">
            <QueryError
              message={context.error}
              onRetry={context.onRetry}
              className="rounded-none border-0"
            />
          </TableCell>
        </TableRow>
      ) : React.Children.toArray(rows).length === 0 ? (
        <TableRow>
          <TableCell
            colSpan={context?.columnCount}
            className="h-40 p-0 text-center text-muted-foreground"
          >
            {context?.search ? (
              <EmptyState
                title="No results match"
                description="Try a different search or clear your filters."
              />
            ) : (
              (context?.emptyState ?? "No results match your filters.")
            )}
          </TableCell>
        </TableRow>
      ) : (
        rows
      )}
    </tbody>
  );
}

function TableFooter({
  className,
  ...props
}: React.HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <tfoot
      data-slot="table-footer"
      className={cn(
        "border-t bg-muted/30 font-medium [&>tr]:last:border-b-0",
        className,
      )}
      {...props}
    />
  );
}

function TableRow({
  className,
  sortValues: _sortValues,
  ...props
}: React.HTMLAttributes<HTMLTableRowElement> & TableRowSortProps) {
  return (
    <tr
      data-slot="table-row"
      className={cn(
        "h-14 border-b transition-colors hover:bg-muted/30 data-[state=selected]:bg-muted",
        className,
      )}
      {...props}
    />
  );
}

/** The same native button drives compound tables and TanStack tables. */
export function TableSortButton({
  children,
  direction,
  onSort,
}: {
  children: React.ReactNode;
  direction: false | "asc" | "desc";
  onSort: () => void;
}) {
  const Icon =
    direction === "asc"
      ? ArrowUp
      : direction === "desc"
        ? ArrowDown
        : ArrowUpDown;
  return (
    <button
      type="button"
      onClick={onSort}
      className="inline-flex min-h-10 max-w-full cursor-pointer items-center justify-[inherit] gap-2 rounded-sm text-inherit outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
      title={
        direction === "asc"
          ? "Sort descending"
          : direction === "desc"
            ? "Clear sorting"
            : "Sort ascending"
      }
    >
      {children}
      <Icon aria-hidden="true" className="size-3.5 shrink-0" />
    </button>
  );
}

function TableHead({
  className,
  children,
  sortKey,
  sortDirection,
  onSort,
  ...props
}: React.ThHTMLAttributes<HTMLTableCellElement> & {
  sortKey?: string;
  sortDirection?: false | "asc" | "desc";
  onSort?: () => void;
}) {
  const context = React.useContext(SortContext);
  const direction = sortKey
    ? context?.sorting?.key === sortKey
      ? context.sorting.direction
      : false
    : (sortDirection ?? false);
  const toggle = sortKey ? () => context?.toggle(sortKey) : onSort;
  return (
    <th
      data-slot="table-head"
      scope="col"
      aria-sort={
        toggle
          ? direction === "asc"
            ? "ascending"
            : direction === "desc"
              ? "descending"
              : "none"
          : undefined
      }
      className={cn(
        "h-11 px-4 text-left align-middle text-xs font-medium text-muted-foreground whitespace-nowrap [&:has([role=checkbox])]:pr-0",
        className,
      )}
      {...props}
    >
      {toggle ? (
        <TableSortButton direction={direction} onSort={toggle}>
          {children}
        </TableSortButton>
      ) : (
        children
      )}
    </th>
  );
}

function TableCell({
  className,
  ...props
}: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td
      data-slot="table-cell"
      className={cn(
        "px-4 py-2.5 align-middle [&>[data-slot=empty-state]]:border-0 [&>[data-slot=empty-state]]:rounded-none [&:has([role=checkbox])]:pr-0",
        className,
      )}
      {...props}
    />
  );
}

function TableCaption({
  className,
  ...props
}: React.HTMLAttributes<HTMLTableCaptionElement>) {
  return (
    <caption
      data-slot="table-caption"
      className={cn("mt-4 text-sm text-muted-foreground", className)}
      {...props}
    />
  );
}

export {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableFooter,
  TableHead,
  TableHeader,
  TableRow,
};
