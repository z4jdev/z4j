/**
 * Static structural-equivalence assertions between the
 * hand-maintained ``api-types.ts`` shapes and the generated
 * ``openapi-types.gen.ts`` (which is ``pnpm openapi:gen``'d from
 * the brain's live OpenAPI snapshot).
 *
 * Why this file exists
 * --------------------
 * ``api-types.ts`` is hand-maintained because every dashboard
 * consumer wants the simple flat ``WorkerPublic`` / ``TaskPublic``
 * / ``UserPublic`` shape rather than the
 * ``components["schemas"]["WorkerPublic"]`` syntax that
 * openapi-typescript emits. Replacing it across 22 files would be
 * pure churn with no user-facing benefit.
 *
 * BUT - we also want the brain Pydantic models to be the source
 * of truth, and the dashboard's hand-typed mirror to fail loudly
 * the moment they drift.
 *
 * This file does the loudly-failing part. For every interface in
 * ``api-types.ts``, a ``StructurallyEquivalent`` type assertion
 * proves the hand-typed shape has the same fields with the same
 * types as the schema component the brain advertises in its
 * OpenAPI document. ``tsc --noEmit`` (run by ``pnpm typecheck``,
 * which CI gates on) fails on any mismatch.
 *
 * How to update it
 * ----------------
 * 1. Add a Pydantic field on the brain side.
 * 2. Restart the brain (or it auto-reloads in dev).
 * 3. Run ``pnpm openapi:fetch && pnpm openapi:gen`` to refresh
 *    the snapshot + generated types.
 * 4. ``pnpm typecheck`` will now fail in this file with
 *    ``DRIFTED_FROM_THE_BRAIN_SCHEMA: "X"``, naming the fields the
 *    hand-typed mirror is missing (or saying every field is present
 *    and one of them has the wrong type).
 * 5. Update ``api-types.ts``; commit both files together.
 *
 * The generated ``openapi-types.gen.ts`` is committed so this
 * check works without a running brain.
 */
import type {
  AgentPublic,
  CommandPublic,
  EventPublic,
  LoginRequest,
  LoginResponse,
  ProjectPublic,
  QueuePublic,
  SchedulePublic,
  TaskPublic,
  UserMembershipSummary,
  UserMePublic,
  UserPublic,
  WorkerPublic,
} from "@/lib/api-types";
import type { components } from "@/lib/openapi-types.gen";

type Schemas = components["schemas"];

/** Fails the build unless its argument is exactly ``true``. */
type Assert<_T extends true> = true;

/**
 * Turns a comparison that collapsed to ``never`` into something
 * ``Assert`` can reject. Wrap EVERY comparison in it.
 *
 * ``never`` is assignable to every type, so ``Assert`` alone lets
 * it through: a conditional type that fails to match produces
 * ``never``, which meant this file's guards were green against
 * precisely the mismatches they exist to catch, and had been since
 * it was written. No constraint can reject ``never`` on its own
 * (that is what a bottom type means), so the collapse has to be
 * detected and replaced before the constraint sees it.
 *
 * ``StructurallyEquivalent`` below is also written so it cannot
 * produce ``never``. This stays as the outer guard because that is
 * a property of one helper, and the hole belongs to the shape:
 * any future comparison written the obvious way falls into it.
 */
type NotNever<T> = [T] extends [never]
  ? { COMPARISON_COLLAPSED_TO_NEVER: true }
  : T;

/** Keys of ``T`` that a value must carry. */
type RequiredKeys<T> = {
  [K in keyof T]-?: Record<string, never> extends Pick<T, K> ? never : K;
}[keyof T];

/**
 * Fields the brain always sends that the hand-typed mirror lacks.
 *
 * Restricted to required keys so the diagnostic names only what
 * actually broke the comparison. Listing every absent key instead
 * buries the one real answer under the optional fields the mirror
 * is free not to carry.
 */
type MissingFields<Hand, Generated> = Exclude<
  RequiredKeys<Generated>,
  keyof Hand
>;

/**
 * Asserts ``Hand`` is structurally a superset of ``Generated``.
 *
 * The check is one-way on purpose: the hand-typed shape MAY add
 * doc-only fields the brain doesn't advertise (e.g. UI-only
 * computed flags) but it MUST cover every field the brain
 * actually returns. Drift in the other direction (a Pydantic
 * field missing from the dashboard) is the actual bug class we're
 * preventing.
 *
 * On failure this resolves to an object type rather than to
 * ``never``, for two reasons. It cannot be silently swallowed by
 * a constraint, and ``tsc`` prints the type inline, so the
 * diagnostic names the drifted fields instead of leaving somebody
 * to diff two large interfaces by eye.
 *
 * ``Hand`` and ``Generated`` are wrapped in tuples so the
 * conditional does not distribute over a union, which is the other
 * route to a silent ``never``.
 */
type StructurallyEquivalent<Hand, Generated> = [Hand] extends [Generated]
  ? true
  : {
      DRIFTED_FROM_THE_BRAIN_SCHEMA: [MissingFields<Hand, Generated>] extends [
        never,
      ]
        ? "every field is present, so one of them has the wrong type here"
        : MissingFields<Hand, Generated>;
    };

// ---------------------------------------------------------------------------
// Per-schema assertions. Each line is a one-token compile-time
// guard. Add a new line whenever a new public response model
// lands. Re-running ``pnpm openapi:gen`` then ``pnpm typecheck``
// is the round-trip.
// ---------------------------------------------------------------------------

// Auth surface
type _UserPublic = Assert<
  NotNever<StructurallyEquivalent<UserPublic, Schemas["UserPublic"]>>
>;
type _UserMePublic = Assert<
  NotNever<StructurallyEquivalent<UserMePublic, Schemas["UserMePublic"]>>
>;
type _LoginRequest = Assert<
  NotNever<StructurallyEquivalent<LoginRequest, Schemas["LoginRequest"]>>
>;
type _LoginResponse = Assert<
  NotNever<StructurallyEquivalent<LoginResponse, Schemas["LoginResponse"]>>
>;
type _UserMembershipSummary = Assert<
  NotNever<
    StructurallyEquivalent<
      UserMembershipSummary,
      Schemas["UserMembershipSummary"]
    >
  >
>;

// Project / agents
type _ProjectPublic = Assert<
  NotNever<StructurallyEquivalent<ProjectPublic, Schemas["ProjectPublic"]>>
>;
type _AgentPublic = Assert<
  NotNever<StructurallyEquivalent<AgentPublic, Schemas["AgentPublic"]>>
>;

// Tasks / Workers / Queues / Schedules / Commands / Events
type _TaskPublic = Assert<
  NotNever<StructurallyEquivalent<TaskPublic, Schemas["TaskPublic"]>>
>;
type _WorkerPublic = Assert<
  NotNever<StructurallyEquivalent<WorkerPublic, Schemas["WorkerPublic"]>>
>;
type _QueuePublic = Assert<
  NotNever<StructurallyEquivalent<QueuePublic, Schemas["QueuePublic"]>>
>;
type _SchedulePublic = Assert<
  NotNever<StructurallyEquivalent<SchedulePublic, Schemas["SchedulePublic"]>>
>;
type _CommandPublic = Assert<
  NotNever<StructurallyEquivalent<CommandPublic, Schemas["CommandPublic"]>>
>;
type _EventPublic = Assert<
  NotNever<StructurallyEquivalent<EventPublic, Schemas["EventPublic"]>>
>;

// Schemas not currently in the assertion set:
// - ``ApiKeyPublic`` lives only as a hook-local type today; not yet
//   mirrored in api-types.ts.
// - ``HealthResponse`` and ``SetupStatusResponse`` are inline-typed
//   dicts on the brain side; once those endpoints get explicit
//   Pydantic response models, add the assertion here.

// All assertions are ``true`` literals, so this file emits no
// runtime code. ``tsc`` evaluates them at build time; failures
// are TypeScript diagnostics, not runtime errors.
export type {};
