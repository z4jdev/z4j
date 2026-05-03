/**
 * Dashboard push socket client.
 *
 * Connects to ``/ws/dashboard``, sends a single ``subscribe`` frame
 * for one project, then dispatches every inbound ``event`` frame to
 * the registered handler. z4j only ever pushes "topic X
 * changed" notifications - it never sends payloads - so the
 * handler's job is to invalidate the matching TanStack Query keys
 * and let the existing REST hooks refetch.
 *
 * Reconnect strategy: exponential backoff capped at 30 s. The
 * socket re-subscribes automatically on every reconnect. Pings are
 * sent every 25 s as a keepalive (browsers tend to kill idle
 * sockets backgrounded for a long time, and intermediaries time
 * out idle WS at 60 s).
 *
 * One instance per project view. Construct via
 * :func:`useDashboardSocket` rather than calling ``new`` directly.
 */

export type DashboardTopic = "task.changed" | "command.changed" | "agent.changed";

export interface DashboardEvent {
  topic: DashboardTopic;
}

export type DashboardEventHandler = (event: DashboardEvent) => void;

interface ServerFrame {
  type?: string;
  topic?: string;
}

const RECONNECT_BACKOFF_MS = [500, 1000, 2000, 5000, 10_000, 30_000] as const;
const PING_INTERVAL_MS = 25_000;

export interface DashboardSocketOptions {
  /** UUID of the project to subscribe to. */
  projectId: string;
  /** Called for every ``event`` frame. */
  onEvent: DashboardEventHandler;
  /** Optional - fired on every reconnect attempt for diagnostics. */
  onStatusChange?: (status: DashboardSocketStatus) => void;
}

export type DashboardSocketStatus =
  | "connecting"
  | "open"
  | "closed"
  | "reconnecting";

export class DashboardSocket {
  private ws: WebSocket | null = null;
  private closed = false;
  private reconnectAttempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private status: DashboardSocketStatus = "connecting";

  private lastPingAt = Date.now();
  private abortController = new AbortController();

  constructor(private opts: DashboardSocketOptions) {
    // Demo build (VITE_Z4J_DEMO_MODE=true): there is no real backend
    // to connect to, so do NOT open a WebSocket. The dashboard's
    // useDashboardSocket consumers degrade gracefully when the
    // socket never reaches "open" -- they just rely on REST refetch
    // intervals instead of push updates. Returning early also
    // ensures the demo build cannot accidentally make any outbound
    // server-side connection: the static-asset GETs to Cloudflare
    // Pages and the in-browser mock-fetch interceptor are the ONLY
    // network egress paths.
    if (import.meta.env.VITE_Z4J_DEMO_MODE === "true") {
      this.closed = true;
      this.setStatus("closed");
      return;
    }
    this.connect();
    // Detect laptop sleep/wake: if the tab was hidden for a long
    // time and becomes visible, force a reconnect - the browser
    // often doesn't fire the WS close event after sleep.
    if (typeof document !== "undefined") {
      document.addEventListener(
        "visibilitychange",
        () => {
          if (
            document.visibilityState === "visible" &&
            Date.now() - this.lastPingAt > PING_INTERVAL_MS * 2
          ) {
            this.ws?.close();
          }
        },
        { signal: this.abortController.signal },
      );
    }
  }

  /** Tear down the socket. Idempotent. */
  close(): void {
    this.closed = true;
    this.clearTimers();
    // AbortController removes all listeners registered with its signal.
    this.abortController.abort();
    if (this.ws) {
      try {
        this.ws.close(1000, "client closed");
      } catch {
        // ignore - already closing
      }
      this.ws = null;
    }
    this.setStatus("closed");
  }

  // ------------------------------------------------------------------
  // Internals
  // ------------------------------------------------------------------

  private connect(): void {
    if (this.closed) return;
    this.setStatus(this.reconnectAttempt === 0 ? "connecting" : "reconnecting");

    const url = this.buildUrl();
    let ws: WebSocket;
    try {
      ws = new WebSocket(url);
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.ws = ws;

    ws.addEventListener("open", () => {
      // Send the single subscribe frame. The server replies with
      // {type:"ready"} which we treat as the "fully connected"
      // signal - but we mark "open" as soon as the WS opens so the
      // UI can stop the spinner immediately.
      this.setStatus("open");
      this.reconnectAttempt = 0;
      try {
        ws.send(
          JSON.stringify({ type: "subscribe", project_id: this.opts.projectId }),
        );
      } catch {
        // send failed - let the close handler reconnect
      }
      this.startPingLoop();
    });

    ws.addEventListener("message", (ev: MessageEvent<string>) => {
      let frame: ServerFrame;
      try {
        frame = JSON.parse(ev.data) as ServerFrame;
      } catch {
        return;
      }
      if (frame.type === "event" && isDashboardTopic(frame.topic)) {
        this.opts.onEvent({ topic: frame.topic });
      }
      // ready / pong are treated as no-ops - they exist for the
      // server's benefit (it knows we're alive when we PONG back).
    });

    ws.addEventListener("close", () => {
      this.clearPingTimer();
      this.ws = null;
      if (!this.closed) {
        this.scheduleReconnect();
      }
    });

    ws.addEventListener("error", () => {
      // Most browsers fire close() right after error() - we let
      // the close handler do the reconnect to avoid double-firing.
    });
  }

  private buildUrl(): string {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${window.location.host}/ws/dashboard`;
  }

  private startPingLoop(): void {
    this.clearPingTimer();
    this.lastPingAt = Date.now();
    this.pingTimer = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        try {
          this.ws.send(JSON.stringify({ type: "ping" }));
          this.lastPingAt = Date.now();
        } catch {
          // close handler will reconnect
        }
      }
    }, PING_INTERVAL_MS);
  }

  private clearPingTimer(): void {
    if (this.pingTimer !== null) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
  }

  private scheduleReconnect(): void {
    if (this.closed) return;
    this.setStatus("reconnecting");
    const idx = Math.min(this.reconnectAttempt, RECONNECT_BACKOFF_MS.length - 1);
    const base = RECONNECT_BACKOFF_MS[idx];
    // Add +/-20% jitter so N tabs don't thundering-herd the brain
    // on restart. Without this, every dashboard reconnects at the
    // exact same moment after every backoff tick.
    const jitter = base * 0.2 * (Math.random() * 2 - 1);
    const delay = Math.max(100, Math.round(base + jitter));
    this.reconnectAttempt += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  private clearTimers(): void {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.clearPingTimer();
  }

  private setStatus(next: DashboardSocketStatus): void {
    if (this.status === next) return;
    this.status = next;
    this.opts.onStatusChange?.(next);
  }
}

function isDashboardTopic(t: unknown): t is DashboardTopic {
  return (
    t === "task.changed" || t === "command.changed" || t === "agent.changed"
  );
}
