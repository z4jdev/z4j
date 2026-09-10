import { Button } from "@/components/ui/button";
import { ChevronLeft, ChevronRight, ChevronsLeft } from "lucide-react";

/** Cursor navigation keeps its place even when a page is empty or unavailable. */
export function PaginationControls({
  hasPreviousPage,
  hasNextPage,
  onFirstPage,
  onPreviousPage,
  onNextPage,
  pending = false,
}: {
  hasPreviousPage: boolean;
  hasNextPage: boolean;
  onFirstPage?: () => void;
  onPreviousPage?: () => void;
  onNextPage?: () => void;
  pending?: boolean;
}) {
  return (
    <nav aria-label="Table pages" className="flex shrink-0 items-center gap-1">
      {onFirstPage && (
        <Button
          variant="outline"
          size="icon"
          disabled={pending || !hasPreviousPage}
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
          disabled={pending || !hasPreviousPage}
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
          disabled={pending || !hasNextPage}
          onClick={onNextPage}
          aria-label="Go to next page"
        >
          <ChevronRight className="size-4" />
        </Button>
      )}
    </nav>
  );
}
