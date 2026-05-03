/**
 * Per-engine capability map for the schedule create / edit form.
 *
 * docs/SCHEDULER.md §13.1 promises "form fields gate per engine
 * capability (no priority field when engine is RQ, etc.)" The form
 * uses this map to:
 *
 * - Filter the ``kind`` dropdown to the kinds that engine actually
 *   supports (no ``solar`` for RQ, no ``one_shot`` for arq, etc.).
 * - Show inline notes when a field doesn't apply to the chosen
 *   (engine, kind) pair (e.g. queue field disabled for arq, which
 *   addresses tasks by function name with no broker-side queue).
 * - Surface a per-engine hint on the queue placeholder so operators
 *   coming from celery don't paste a routing key into a Redis
 *   broker that ignores it.
 *
 * The map covers the six engines z4j-core's spec lists (§4.1 and
 * §12). Adding a new engine = adding one entry here. Unknown
 * engines fall back to "everything allowed" so the form doesn't
 * silently restrict schedules for a future engine adapter.
 */

export type ScheduleKind = "cron" | "interval" | "one_shot" | "solar";

export interface EngineCaps {
  /** Kinds the engine + its z4j adapter pair supports. */
  kinds: ScheduleKind[];
  /**
   * Whether the engine's broker concept maps to a "queue routing
   * key." False for engines that enqueue by task name only
   * (arq is the canonical example - all jobs go to the same
   * Redis stream and are dispatched to whichever worker is free).
   */
  hasQueues: boolean;
  /**
   * Operator-facing note rendered next to the queue field
   * explaining what queue means for this engine. Empty when the
   * default "default" placeholder is fine.
   */
  queueHint: string;
}

/**
 * Conservative defaults applied to engines this map doesn't know
 * about. Allows everything so a brand-new engine adapter doesn't
 * break the form before the map is updated.
 */
const _DEFAULT_CAPS: EngineCaps = {
  kinds: ["cron", "interval", "one_shot", "solar"],
  hasQueues: true,
  queueHint: "",
};

/**
 * Per-engine capabilities. Keep these honest - the form gates on
 * this so a wrong entry produces a wrong UX. When in doubt err
 * toward "supported" so we don't block legitimate workflows.
 */
const _ENGINE_CAPS: Record<string, EngineCaps> = {
  celery: {
    // celery via z4j-celery + (z4j-celerybeat | z4j-scheduler) is
    // the most capable adapter pair. All four kinds work.
    kinds: ["cron", "interval", "one_shot", "solar"],
    hasQueues: true,
    queueHint:
      "Celery routing key. Maps to broker queue (RabbitMQ vhost queue / Redis list).",
  },
  rq: {
    // RQ has cron via rq-scheduler + interval + one-shot via
    // enqueue_at. No native solar support; operator who needs
    // solar on RQ would compute the next event in their task and
    // re-enqueue.
    kinds: ["cron", "interval", "one_shot"],
    hasQueues: true,
    queueHint: "RQ queue name. Workers attach to one or more named queues.",
  },
  dramatiq: {
    // Dramatiq supports cron via dramatiq-crontab + interval.
    // No native one-shot or solar.
    kinds: ["cron", "interval"],
    hasQueues: true,
    queueHint:
      "Dramatiq queue name. Brokers (Redis / RabbitMQ) keep one queue per name.",
  },
  arq: {
    // arq has cron jobs (defined statically, not dynamic) + delayed
    // jobs (one_shot equivalent via enqueue_job(_defer_until=...)).
    // No queue concept - all jobs go to one Redis stream.
    kinds: ["cron", "interval", "one_shot"],
    hasQueues: false,
    queueHint:
      "arq has no queue routing - all jobs share one Redis stream.",
  },
  huey: {
    // Huey supports periodic tasks (cron + interval) but not
    // one-shot in the same primitive. Solar via task-side computation.
    kinds: ["cron", "interval"],
    hasQueues: true,
    queueHint:
      "Huey supports a single named queue per Huey instance.",
  },
  taskiq: {
    // taskiq supports scheduling via taskiq-scheduler. Most
    // brokers support queue routing.
    kinds: ["cron", "interval", "one_shot"],
    hasQueues: true,
    queueHint:
      "taskiq label that the broker routes on (e.g. RabbitMQ binding key).",
  },
};

/**
 * Returns the capability set for ``engine``. Unknown engines get
 * the permissive default so a new adapter's schedules can be
 * managed in the dashboard immediately, with operator-facing
 * gating refined in a follow-up.
 */
export function capsForEngine(engine: string): EngineCaps {
  return _ENGINE_CAPS[engine.toLowerCase()] ?? _DEFAULT_CAPS;
}

/**
 * True when the (engine, kind) pair is supported. Wraps
 * ``capsForEngine`` for the very common "is this option valid?"
 * check the form's kind dropdown does on every render.
 */
export function isKindSupported(engine: string, kind: ScheduleKind): boolean {
  return capsForEngine(engine).kinds.includes(kind);
}
