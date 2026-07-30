import { beforeEach, describe, expect, it } from "vitest";

import {
  apiPathFromLocation,
  bulkRetryStorageKey,
  clearStoredBulkRetry,
  hasSameBulkRetrySelection,
  hasStoredBulkRetryRecord,
  isTerminalBulkRetry,
  parseStoredBulkRetryBody,
  persistBulkRetry,
  readStoredBulkRetry,
  storedBulkRetryMatchesResource,
  type DurableBulkRetryBody,
} from "@/lib/bulk-retry-storage";

describe("durable bulk-retry browser record", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("round-trips the exact key, canonical body, and Location", () => {
    const body: DurableBulkRetryBody = {
      idempotency_key: "fixed-key",
      filter: {
        state: "failure",
        name: "billing",
        priority: ["critical", "high"],
        search: "needle",
      },
      max: 1000,
    };
    const canonicalBody = JSON.stringify(body);

    expect(
      persistBulkRetry("project", {
        key: body.idempotency_key,
        canonicalBody,
        location: null,
      }),
    ).toBe(true);
    expect(readStoredBulkRetry("project")).toEqual({
      key: "fixed-key",
      canonicalBody,
      location: null,
    });
    expect(hasStoredBulkRetryRecord("project")).toBe(true);
    expect(parseStoredBulkRetryBody(readStoredBulkRetry("project")!)).toEqual(
      body,
    );

    expect(
      persistBulkRetry("project", {
        key: body.idempotency_key,
        canonicalBody,
        location: "/api/v1/projects/project/bulk-retry-requests/request-id",
      }),
    ).toBe(true);
    expect(readStoredBulkRetry("project")?.location).toBe(
      "/api/v1/projects/project/bulk-retry-requests/request-id",
    );
  });

  it("fails closed when storage cannot be written", () => {
    const unavailable = {
      setItem() {
        throw new DOMException("quota", "QuotaExceededError");
      },
    } as unknown as Storage;
    expect(
      persistBulkRetry(
        "project",
        { key: "k", canonicalBody: "{}", location: null },
        unavailable,
      ),
    ).toBe(false);
  });

  it("rejects malformed records and clears resolved records", () => {
    window.localStorage.setItem(
      bulkRetryStorageKey("project"),
      JSON.stringify({ key: "k", canonicalBody: 7, location: null }),
    );
    expect(readStoredBulkRetry("project")).toBeNull();

    persistBulkRetry("project", {
      key: "k",
      canonicalBody: "{}",
      location: null,
    });
    clearStoredBulkRetry("project");
    expect(readStoredBulkRetry("project")).toBeNull();
    expect(hasStoredBulkRetryRecord("project")).toBe(false);
  });

  it("distinguishes an absent record from an unsafe corrupted record", () => {
    expect(hasStoredBulkRetryRecord("project")).toBe(false);
    window.localStorage.setItem(
      bulkRetryStorageKey("project"),
      JSON.stringify({
        key: "expected-key",
        canonicalBody: JSON.stringify({
          idempotency_key: "different-key",
          filter: { state: "failure" },
          max: 1000,
        }),
        location: null,
      }),
    );
    expect(hasStoredBulkRetryRecord("project")).toBe(true);
    expect(readStoredBulkRetry("project")).toBeNull();
  });

  it("refuses to conflate unresolved requests for different filters", () => {
    const prior: DurableBulkRetryBody = {
      idempotency_key: "k",
      filter: {
        state: "failure",
        name: "billing",
        priority: ["critical"],
        search: "needle",
      },
      max: 1000,
    };
    expect(
      hasSameBulkRetrySelection(prior, {
        filter: {
          state: "failure",
          name: "billing",
          priority: ["critical"],
          search: "needle",
        },
        max: 1000,
      }),
    ).toBe(true);
    expect(
      hasSameBulkRetrySelection(prior, {
        filter: { state: "failure", name: "email" },
        max: 1000,
      }),
    ).toBe(false);
    expect(
      hasSameBulkRetrySelection(prior, {
        filter: {
          state: "failure",
          name: "billing",
          priority: ["low"],
          search: "needle",
        },
        max: 1000,
      }),
    ).toBe(false);
    expect(
      hasSameBulkRetrySelection(prior, {
        filter: {
          state: "failure",
          name: "billing",
          priority: ["critical"],
          search: "different",
        },
        max: 1000,
      }),
    ).toBe(false);
  });

  it("only strips the exact API v1 path prefix", () => {
    expect(
      apiPathFromLocation(
        "/api/v1/projects/project/bulk-retry-requests/01234567-89ab-4def-8123-456789abcdef",
        "project",
      ),
    ).toBe(
      "/projects/project/bulk-retry-requests/01234567-89ab-4def-8123-456789abcdef",
    );
    expect(
      apiPathFromLocation(
        "/api/v1/projects/other/bulk-retry-requests/01234567-89ab-4def-8123-456789abcdef",
        "project",
      ),
    ).toBeNull();
    expect(
      apiPathFromLocation("/api/v10/projects/project", "project"),
    ).toBeNull();
  });

  it("binds a stored Location to the exact server key and resource id", () => {
    const stored = {
      key: "fixed-key",
      canonicalBody: "{}",
      location:
        "/api/v1/projects/project/bulk-retry-requests/01234567-89ab-4def-8123-456789abcdef",
    };
    expect(
      storedBulkRetryMatchesResource(stored, {
        id: "01234567-89ab-4def-8123-456789abcdef",
        idempotency_key: "fixed-key",
      }),
    ).toBe(true);
    expect(
      storedBulkRetryMatchesResource(stored, {
        id: "11234567-89ab-4def-8123-456789abcdef",
        idempotency_key: "fixed-key",
      }),
    ).toBe(false);
    expect(
      storedBulkRetryMatchesResource(stored, {
        id: "01234567-89ab-4def-8123-456789abcdef",
        idempotency_key: "different-key",
      }),
    ).toBe(false);
  });

  it("does not clear paused, blocked, or in-progress parents", () => {
    for (const status of ["paused", "blocked", "in_progress"]) {
      expect(isTerminalBulkRetry(status)).toBe(false);
    }
    for (const status of [
      "no_match",
      "succeeded",
      "failed",
      "partial",
      "indeterminate",
    ]) {
      expect(isTerminalBulkRetry(status)).toBe(true);
    }
  });
});
