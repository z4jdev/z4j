/**
 * Warm the dev server before any test runs.
 *
 * The visual-regression project runs FIRST (the functional spine depends on
 * it, so baselines observe a freshly bootstrapped database) and it sets
 * `retries: 0` on purpose, because a retried pixel comparison hides a real
 * regression behind a lucky second attempt.
 *
 * The combination is fragile: in CI the suite starts immediately after
 * `playwright install`, so the very first navigation pays Vite's cold-start
 * cost. A measured cold start on this stack was 32 seconds, and one local run
 * had "Home dashboard" time out on `goto("/")` before the page ever rendered.
 * That failure looks exactly like a visual regression in the CI log while
 * being nothing of the sort.
 *
 * Warming here fixes the cause rather than the symptom: no retry is added and
 * no threshold is widened, the server is simply ready before the first
 * screenshot is taken.
 */
import type { FullConfig } from "@playwright/test";

const WARMUP_TIMEOUT_MS = 120_000;
const POLL_INTERVAL_MS = 1_000;
// Two consecutive fast responses mean the module graph is compiled and
// cached, not merely that the socket accepted a connection.
const FAST_RESPONSE_MS = 3_000;
const REQUIRED_FAST_RESPONSES = 2;

async function probe(url: string): Promise<number | null> {
  const started = Date.now();
  try {
    const response = await fetch(url, { redirect: "manual" });
    // Drain the body so the timing reflects a fully served response.
    await response.arrayBuffer().catch(() => undefined);
    return response.ok || response.status < 500 ? Date.now() - started : null;
  } catch {
    return null;
  }
}

export default async function globalSetup(config: FullConfig): Promise<void> {
  const baseURL =
    config.projects[0]?.use?.baseURL ??
    process.env.Z4J_E2E_BASE_URL ??
    "http://localhost:7701";

  const deadline = Date.now() + WARMUP_TIMEOUT_MS;
  let consecutiveFast = 0;
  let lastDuration: number | null = null;

  while (Date.now() < deadline) {
    lastDuration = await probe(baseURL);
    if (lastDuration !== null && lastDuration < FAST_RESPONSE_MS) {
      consecutiveFast += 1;
      if (consecutiveFast >= REQUIRED_FAST_RESPONSES) {
        console.log(
          `[global-setup] ${baseURL} warm (last response ${lastDuration}ms)`,
        );
        return;
      }
    } else {
      consecutiveFast = 0;
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }

  // Do not fail the run here. If the server is genuinely down the tests
  // report that far more clearly than a setup hook can, and failing here
  // would turn an infrastructure blip into an unexplained suite abort.
  console.warn(
    `[global-setup] ${baseURL} did not warm within ${WARMUP_TIMEOUT_MS}ms ` +
      `(last probe: ${lastDuration === null ? "unreachable" : `${lastDuration}ms`}). ` +
      "Continuing; the first navigation may be slow.",
  );
}
