/**
 * What the brain and the engine adapters do with the dashboard's per-task
 * Retry and Cancel commands, stated once so the task list and the task
 * detail page offer the same controls and say the same thing.
 */

/**
 * Engines whose retry the brain accepts without operator arguments.
 *
 * Mirrors ``NATIVE_RETRY_ENGINES`` in
 * ``packages/z4j/backend/src/z4j_brain/domain/retry_contract.py``; change
 * both together. For every other engine the brain answers 409 unless the
 * request carries both ``override_args`` and ``override_kwargs``: the agent
 * re-submits the task, and the brain stores the original arguments redacted.
 * The dashboard sends no overrides, so it offers Retry only for these.
 */
export const NATIVE_RETRY_ENGINES: ReadonlySet<string> = new Set([
  "celery",
  "rq",
]);

/** Display names of {@link NATIVE_RETRY_ENGINES}, for operator copy. */
const NATIVE_RETRY_LABEL = "Celery and RQ";

export function isNativeRetryEngine(engine: string): boolean {
  return NATIVE_RETRY_ENGINES.has(engine);
}

/**
 * Why the brain would refuse a dashboard Retry for these engines, or
 * ``undefined`` when it would accept one for all of them.
 */
export function retryUnavailableReason(
  engines: Iterable<string>,
): string | undefined {
  const refused = [...new Set(engines)].filter(
    (engine) => !isNativeRetryEngine(engine),
  );
  if (refused.length === 0) return undefined;
  return (
    `Retry here works for ${NATIVE_RETRY_LABEL} tasks only. ` +
    `A ${refused.sort().join(", ")} retry re-submits the task with its ` +
    "arguments, which z4j stores redacted."
  );
}

/**
 * What a cancel command does on each engine, from the adapters' cancel
 * actions (``packages/z4j-<engine>/src``). Shown where the operator
 * confirms, because Celery, RQ and arq can stop a task mid-run.
 */
const CANCEL_EFFECTS: Record<string, string> = {
  celery:
    "Celery revokes the task: a queued task does not start, and a running task is terminated (SIGTERM).",
  rq: "RQ removes a queued job and has the worker terminate a running one.",
  arq: "arq aborts the job, queued or running, only when its worker sets allow_abort_jobs.",
  huey: "Huey stops a queued task from starting; a running task is not stopped.",
  dramatiq:
    "Dramatiq stops a queued message from starting; running work is not stopped.",
};

export function cancelEffect(engine: string): string {
  return (
    CANCEL_EFFECTS[engine] ??
    `The ${engine} adapter decides whether a running task is stopped.`
  );
}
