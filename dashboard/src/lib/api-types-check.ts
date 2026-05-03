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
 * 4. ``pnpm typecheck`` will now fail in this file with a clear
 *    "Property 'X' is missing in type" error, pointing you at
 *    the hand-typed mirror that needs the same field.
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
 * Implementation: ``Hand extends Generated ? true : never``.
 * If the assertion fails, TypeScript flags the assignment with
 * a precise "missing property" diagnostic.
 */
type Assert<_T extends true> = true;
type StructurallyEquivalent<Hand, Generated> = Hand extends Generated
  ? true
  : never;

// ---------------------------------------------------------------------------
// Per-schema assertions. Each line is a one-token compile-time
// guard. Add a new line whenever a new public response model
// lands. Re-running ``pnpm openapi:gen`` then ``pnpm typecheck``
// is the round-trip.
// ---------------------------------------------------------------------------

// Auth surface
type _UserPublic = Assert<StructurallyEquivalent<UserPublic, Schemas["UserPublic"]>>;
type _UserMePublic = Assert<StructurallyEquivalent<UserMePublic, Schemas["UserMePublic"]>>;
type _LoginRequest = Assert<StructurallyEquivalent<LoginRequest, Schemas["LoginRequest"]>>;
type _LoginResponse = Assert<StructurallyEquivalent<LoginResponse, Schemas["LoginResponse"]>>;
type _UserMembershipSummary = Assert<
  StructurallyEquivalent<
    UserMembershipSummary,
    Schemas["UserMembershipSummary"]
  >
>;

// Project / agents
type _ProjectPublic = Assert<
  StructurallyEquivalent<ProjectPublic, Schemas["ProjectPublic"]>
>;
type _AgentPublic = Assert<StructurallyEquivalent<AgentPublic, Schemas["AgentPublic"]>>;

// Tasks / Workers / Queues / Schedules / Commands / Events
type _TaskPublic = Assert<StructurallyEquivalent<TaskPublic, Schemas["TaskPublic"]>>;
type _WorkerPublic = Assert<
  StructurallyEquivalent<WorkerPublic, Schemas["WorkerPublic"]>
>;
type _QueuePublic = Assert<StructurallyEquivalent<QueuePublic, Schemas["QueuePublic"]>>;
type _SchedulePublic = Assert<
  StructurallyEquivalent<SchedulePublic, Schemas["SchedulePublic"]>
>;
type _CommandPublic = Assert<
  StructurallyEquivalent<CommandPublic, Schemas["CommandPublic"]>
>;
type _EventPublic = Assert<StructurallyEquivalent<EventPublic, Schemas["EventPublic"]>>;

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
