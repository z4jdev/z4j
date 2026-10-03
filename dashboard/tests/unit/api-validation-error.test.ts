import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiCall } from "@/lib/api";

afterEach(() => {
  vi.unstubAllGlobals();
});

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("ApiError validation envelopes", () => {
  it("folds FastAPI's pydantic list detail into a readable validation error", async () => {
    // What a field-validator failure on API-key creation returns (a bad
    // CIDR in ``allowed_cidrs``): FastAPI's default 422 body, not the
    // z4j envelope.
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(422, {
          detail: [
            {
              type: "value_error",
              loc: ["body", "allowed_cidrs"],
              msg: "Value error, allowed_cidrs entry '10.0.0.0/99' is not a valid IPv4 or IPv6 CIDR",
              input: ["10.0.0.0/99"],
            },
          ],
        }),
      ),
    );

    await expect(
      apiCall("/api-keys", {
        method: "POST",
        body: { name: "ci", scopes: [], allowed_cidrs: ["10.0.0.0/99"] },
      }),
    ).rejects.toMatchObject({
      status: 422,
      code: "validation_error",
      message:
        "allowed_cidrs: Value error, allowed_cidrs entry '10.0.0.0/99' is not a valid IPv4 or IPv6 CIDR",
      requestId: null,
    });
  });

  it("names each failing field and joins several entries", () => {
    const error = new ApiError(422, {
      detail: [
        {
          loc: ["body", "name"],
          msg: "String should have at least 1 character",
          type: "string_too_short",
        },
        {
          loc: ["body", "allowed_cidrs", 2],
          msg: "value is not a valid IPv4 or IPv6 CIDR",
          type: "value_error",
        },
        {
          loc: ["query", "limit"],
          msg: "Input should be less than or equal to 500",
          type: "less_than_equal",
        },
      ],
    });

    expect(error.code).toBe("validation_error");
    expect(error.message).toBe(
      [
        "name: String should have at least 1 character",
        "allowed_cidrs: value is not a valid IPv4 or IPv6 CIDR",
        "limit: Input should be less than or equal to 500",
      ].join("; "),
    );
    expect(error.details).toEqual({
      errors: [
        expect.objectContaining({ loc: ["body", "name"] }),
        expect.objectContaining({ loc: ["body", "allowed_cidrs", 2] }),
        expect.objectContaining({ loc: ["query", "limit"] }),
      ],
    });
  });

  it("drops the prefix when an entry names no field", () => {
    const error = new ApiError(422, {
      detail: [
        {
          loc: ["body"],
          msg: "Value error, at least one of x or y is required",
          type: "value_error",
        },
        { msg: "Field required", type: "missing" },
        { loc: ["body", "name"], type: "missing" },
      ],
    });

    expect(error.message).toBe(
      "Value error, at least one of x or y is required; Field required",
    );
  });

  it("falls back to the status line for an empty list", () => {
    const error = new ApiError(422, { detail: [] });

    expect(error.code).toBe("validation_error");
    expect(error.message).toBe("request failed (422)");
    expect(error.details).toEqual({ errors: [] });
  });

  it("keeps the dict-shaped detail envelope unchanged", () => {
    const error = new ApiError(400, {
      detail: {
        error: "matching task count exceeds max",
        max: 1000,
        matched_at_least: 1001,
      },
    });

    expect(error.code).toBe("matching task count exceeds max");
    expect(error.message).toBe("matching task count exceeds max");
    expect(error.details).toEqual({ max: 1000, matched_at_least: 1001 });
  });

  it("keeps the z4j top-level envelope unchanged", () => {
    const error = new ApiError(403, {
      error: "forbidden",
      message: "auditor or admin role required",
      request_id: "req-1",
      details: { required_role: "auditor" },
    });

    expect(error.code).toBe("forbidden");
    expect(error.message).toBe("auditor or admin role required");
    expect(error.requestId).toBe("req-1");
    expect(error.details).toEqual({ required_role: "auditor" });
  });
});
