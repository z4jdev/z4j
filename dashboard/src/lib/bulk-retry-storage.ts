import type { TaskPriority, TaskState } from "@/lib/api-types";

export interface DurableBulkRetryBody {
  idempotency_key: string;
  filter: {
    state: TaskState;
    name?: string;
    priority?: TaskPriority[];
    search?: string;
  };
  max: number;
}

export interface StoredBulkRetry {
  key: string;
  canonicalBody: string;
  location: string | null;
}

const TERMINAL_BULK_RETRY_STATES = new Set([
  "no_match",
  "succeeded",
  "failed",
  "partial",
  "indeterminate",
]);
const TASK_PRIORITIES = new Set<TaskPriority>([
  "critical",
  "high",
  "normal",
  "low",
]);

export function bulkRetryStorageKey(slug: string): string {
  return `z4j:bulk-retry-request:${slug}`;
}

export function hasStoredBulkRetryRecord(
  slug: string,
  storage: Storage = window.localStorage,
): boolean {
  try {
    return storage.getItem(bulkRetryStorageKey(slug)) !== null;
  } catch {
    // An unreadable store cannot prove there is no unresolved operation.
    return true;
  }
}

export function parseStoredBulkRetryBody(
  value: StoredBulkRetry,
): DurableBulkRetryBody | null {
  try {
    const parsed = JSON.parse(value.canonicalBody) as unknown;
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      return null;
    }
    const body = parsed as Record<string, unknown>;
    if (
      Object.keys(body).some(
        (key) => !["idempotency_key", "filter", "max"].includes(key),
      ) ||
      body.idempotency_key !== value.key ||
      !Number.isInteger(body.max) ||
      (body.max as number) < 1 ||
      (body.max as number) > 10_000 ||
      typeof body.filter !== "object" ||
      body.filter === null ||
      Array.isArray(body.filter)
    ) {
      return null;
    }
    const filter = body.filter as Record<string, unknown>;
    if (
      Object.keys(filter).some(
        (key) => !["state", "name", "priority", "search"].includes(key),
      ) ||
      typeof filter.state !== "string" ||
      ("name" in filter && typeof filter.name !== "string") ||
      ("search" in filter && typeof filter.search !== "string") ||
      ("priority" in filter &&
        (!Array.isArray(filter.priority) ||
          filter.priority.length === 0 ||
          filter.priority.some(
            (value) =>
              typeof value !== "string" ||
              !TASK_PRIORITIES.has(value as TaskPriority),
          )))
    ) {
      return null;
    }
    return parsed as DurableBulkRetryBody;
  } catch {
    return null;
  }
}

export function hasSameBulkRetrySelection(
  body: DurableBulkRetryBody,
  selection: Omit<DurableBulkRetryBody, "idempotency_key">,
): boolean {
  const bodyPriorities = body.filter.priority ?? [];
  const selectionPriorities = selection.filter.priority ?? [];
  return (
    body.max === selection.max &&
    body.filter.state === selection.filter.state &&
    body.filter.name === selection.filter.name &&
    body.filter.search === selection.filter.search &&
    bodyPriorities.length === selectionPriorities.length &&
    bodyPriorities.every(
      (priority, index) => priority === selectionPriorities[index],
    )
  );
}

export function readStoredBulkRetry(
  slug: string,
  storage: Storage = window.localStorage,
): StoredBulkRetry | null {
  try {
    const raw = storage.getItem(bulkRetryStorageKey(slug));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<StoredBulkRetry>;
    if (
      typeof parsed.key !== "string" ||
      typeof parsed.canonicalBody !== "string" ||
      !(typeof parsed.location === "string" || parsed.location === null)
    ) {
      return null;
    }
    const stored = parsed as StoredBulkRetry;
    return parseStoredBulkRetryBody(stored) === null ? null : stored;
  } catch {
    return null;
  }
}

export function persistBulkRetry(
  slug: string,
  value: StoredBulkRetry,
  storage: Storage = window.localStorage,
): boolean {
  try {
    storage.setItem(bulkRetryStorageKey(slug), JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

export function clearStoredBulkRetry(
  slug: string,
  storage: Storage = window.localStorage,
): void {
  try {
    storage.removeItem(bulkRetryStorageKey(slug));
  } catch {
    // A completed resource is safe even if browser storage is unavailable.
  }
}

export function apiPathFromLocation(
  location: string,
  slug: string,
): string | null {
  const prefix = `/api/v1/projects/${slug}/bulk-retry-requests/`;
  if (!location.startsWith(prefix)) return null;
  const requestId = location.slice(prefix.length);
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      requestId,
    )
  ) {
    return null;
  }
  return location.slice("/api/v1".length);
}

export function storedBulkRetryMatchesResource(
  stored: StoredBulkRetry,
  resource: { id: string; idempotency_key: string },
): boolean {
  if (stored.location === null) return false;
  return (
    resource.idempotency_key === stored.key &&
    stored.location.endsWith(`/${resource.id}`)
  );
}

export function isTerminalBulkRetry(status: string): boolean {
  return TERMINAL_BULK_RETRY_STATES.has(status);
}
