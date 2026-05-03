/**
 * Hooks for the per-user notification system.
 *
 * Three resource families:
 *
 * - Project channels (admin-managed shared destinations)
 *   GET/POST/PATCH/DELETE /projects/{slug}/notifications/channels
 *
 * - User channels (personal destinations)
 *   GET/POST/PATCH/DELETE /user/channels
 *
 * - User subscriptions (per-user, per-(project,trigger) routing rules)
 *   GET/POST/PATCH/DELETE /user/subscriptions
 *
 * - User notifications (the in-app inbox)
 *   GET /user/notifications
 *   GET /user/notifications/unread-count
 *   POST /user/notifications/{id}/read
 *   POST /user/notifications/read-all
 *
 * - Project default subscriptions (admin onboarding templates)
 *   GET/POST/DELETE /projects/{slug}/notifications/defaults
 *
 * - Delivery audit log (admin-only)
 *   GET /projects/{slug}/notifications/deliveries
 */
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "@/lib/api";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ChannelType =
  | "webhook"
  | "email"
  | "slack"
  | "telegram"
  | "pagerduty"
  | "discord";

export type TriggerType =
  | "task.failed"
  | "task.succeeded"
  | "task.retried"
  | "task.slow"
  | "agent.offline"
  | "agent.online"
  // Synthetic trigger written by /channels/test (1.0.14+) so the
  // deliveries page can show "test" badge and operators have an
  // audit trail of test fires. Not a real subscription trigger.
  | "test.dispatch";

// -- Project channels (shared) ------------------------------------------------

export interface NotificationChannel {
  id: string;
  project_id: string;
  name: string;
  type: ChannelType;
  config: Record<string, unknown>;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateChannelRequest {
  name: string;
  type: ChannelType;
  config: Record<string, unknown>;
  is_active?: boolean;
}

export interface UpdateChannelRequest {
  name?: string;
  config?: Record<string, unknown>;
  is_active?: boolean;
}

// -- User channels ------------------------------------------------------------

export interface UserChannel {
  id: string;
  name: string;
  type: ChannelType;
  config: Record<string, unknown>;
  is_verified: boolean;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateUserChannelRequest {
  name: string;
  type: ChannelType;
  config: Record<string, unknown>;
  is_active?: boolean;
}

export interface UpdateUserChannelRequest {
  name?: string;
  config?: Record<string, unknown>;
  is_active?: boolean;
}

// -- User subscriptions -------------------------------------------------------

export interface UserSubscription {
  id: string;
  user_id: string;
  project_id: string;
  trigger: TriggerType;
  filters: Record<string, unknown>;
  in_app: boolean;
  project_channel_ids: string[];
  user_channel_ids: string[];
  muted_until: string | null;
  cooldown_seconds: number;
  last_fired_at: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateSubscriptionRequest {
  project_id: string;
  trigger: TriggerType;
  filters?: Record<string, unknown>;
  in_app?: boolean;
  project_channel_ids?: string[];
  user_channel_ids?: string[];
  cooldown_seconds?: number;
}

export interface UpdateSubscriptionRequest {
  /** Renaming the trigger added v1.0.18; backend defends the
   *  (user, project, trigger) uniqueness invariant with a 409. */
  trigger?: TriggerType;
  filters?: Record<string, unknown>;
  in_app?: boolean;
  project_channel_ids?: string[];
  user_channel_ids?: string[];
  cooldown_seconds?: number;
  muted_until?: string | null;
  is_active?: boolean;
}

// -- In-app notifications (the bell) ------------------------------------------

export interface UserNotification {
  id: string;
  project_id: string;
  subscription_id: string | null;
  trigger: TriggerType;
  reason: "subscribed" | "default" | "mentioned";
  title: string;
  body: string | null;
  data: Record<string, unknown>;
  read_at: string | null;
  created_at: string;
}

// -- Project default subscriptions (admin) ------------------------------------

export interface ProjectDefaultSubscription {
  id: string;
  project_id: string;
  trigger: TriggerType;
  filters: Record<string, unknown>;
  in_app: boolean;
  project_channel_ids: string[];
  cooldown_seconds: number;
  created_at: string;
}

export interface CreateDefaultSubscriptionRequest {
  trigger: TriggerType;
  filters?: Record<string, unknown>;
  in_app?: boolean;
  project_channel_ids?: string[];
  cooldown_seconds?: number;
}

/**
 * Body for `PATCH /defaults/{default_id}` (added v1.0.18).
 * Every field is optional - only the keys actually present in the
 * request mutate the row. Lets admins flip a single channel on/off,
 * change the cooldown, or rename the trigger without re-typing the
 * whole subscription.
 */
export interface UpdateDefaultSubscriptionRequest {
  trigger?: TriggerType;
  filters?: Record<string, unknown>;
  in_app?: boolean;
  project_channel_ids?: string[];
  cooldown_seconds?: number;
}

/**
 * Cursor-paginated personal delivery history. v1.0.18 added the
 * `/api/v1/user/deliveries` endpoint so users can see "where did
 * my alerts land?" without opening every project's audit log.
 */
export interface UserDeliveryListResponse {
  items: NotificationDelivery[];
  next_cursor: string | null;
}

// -- Delivery audit log -------------------------------------------------------

export interface NotificationDelivery {
  id: string;
  /** v1.0.18: project_id is now exposed so the personal delivery
   *  history can group / filter by project, and badge rows whose
   *  project the user is no longer a member of. */
  project_id: string | null;
  subscription_id: string | null;
  channel_id: string | null;
  user_channel_id: string | null;
  trigger: TriggerType;
  task_id: string | null;
  task_name: string | null;
  status: "sent" | "failed" | "skipped";
  response_code: number | null;
  error: string | null;
  sent_at: string;
  // 1.0.14+: backend enriches the page with channel name + type so
  // the dashboard can render a "Channel" column without an N+1
  // fetch. NULL when the channel was deleted, or when the row was
  // an unsaved-config preflight test (no channel exists yet).
  channel_name: string | null;
  channel_type: ChannelType | null;
  // v1.1.0: who manually triggered this row (channel-test fires
  // only). NULL for subscription-driven fires. Set to the calling
  // user's id when they hit the project Channels "Test" button so
  // the row surfaces in their Global Notification Log.
  triggered_by_user_id: string | null;
  // v1.1.0: email of the user identified by triggered_by_user_id,
  // resolved via a single batch query at read time (no N+1). NULL
  // when triggered_by_user_id is NULL or the user was deleted.
  triggered_by_email: string | null;
}

// ---------------------------------------------------------------------------
// Project channels
// ---------------------------------------------------------------------------

export function useChannels(slug: string) {
  return useQuery<NotificationChannel[]>({
    queryKey: ["notification-channels", slug],
    queryFn: () =>
      api.get<NotificationChannel[]>(`/projects/${slug}/notifications/channels`),
    enabled: !!slug,
  });
}

export function useCreateChannel(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateChannelRequest) =>
      api.post<NotificationChannel>(
        `/projects/${slug}/notifications/channels`,
        body,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notification-channels", slug] });
    },
  });
}

export function useUpdateChannel(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: UpdateChannelRequest }) =>
      api.patch<NotificationChannel>(
        `/projects/${slug}/notifications/channels/${id}`,
        body,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notification-channels", slug] });
    },
  });
}

export function useDeleteChannel(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.delete<void>(`/projects/${slug}/notifications/channels/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notification-channels", slug] });
      qc.invalidateQueries({ queryKey: ["user-subscriptions"] });
    },
  });
}

/**
 * Import one of the operator's personal channels into the project
 * as a project-shared channel. Backend copies the row server-side
 * so the unmasked secret never crosses the wire.
 *
 * Permission: project ADMIN. The source must be owned by the
 * caller (no taking over another user's secret).
 */
export function useImportChannelFromUser(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { user_channel_id: string; name?: string }) =>
      api.post<NotificationChannel>(
        `/projects/${slug}/notifications/channels/import_from_user`,
        body,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notification-channels", slug] });
    },
  });
}

// -- Test dispatch (credential preflight) ------------------------------------

export interface ChannelTestResult {
  success: boolean;
  status_code: number | null;
  error: string | null;
  response_body: string | null;
}

/**
 * Dispatch a test notification against an **unsaved** config.
 *
 * Used by the "Test" button inside the create dialog so admins can
 * verify SMTP / webhook / Slack / Telegram credentials before
 * persisting. Backend does not log the delivery to
 * ``notification_deliveries`` - this is a preflight, not a real
 * send.
 */
export function useTestChannelConfig(slug: string) {
  return useMutation({
    mutationFn: (body: { type: ChannelType; config: Record<string, unknown> }) =>
      api.post<ChannelTestResult>(
        `/projects/${slug}/notifications/channels/test`,
        body,
      ),
  });
}

/**
 * Dispatch a test notification against an already-saved channel.
 *
 * Uses the channel's stored config (including secrets the admin
 * entered at create / update time). Admin-only.
 */
export function useTestChannel(slug: string) {
  return useMutation({
    mutationFn: (channelId: string) =>
      api.post<ChannelTestResult>(
        `/projects/${slug}/notifications/channels/${channelId}/test`,
        {},
      ),
  });
}

// ---------------------------------------------------------------------------
// User channels
// ---------------------------------------------------------------------------

export function useUserChannels() {
  return useQuery<UserChannel[]>({
    queryKey: ["user-channels"],
    queryFn: () => api.get<UserChannel[]>(`/user/channels`),
  });
}

export function useCreateUserChannel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateUserChannelRequest) =>
      api.post<UserChannel>(`/user/channels`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["user-channels"] });
    },
  });
}

/**
 * Import a project's channel into the caller's personal channels.
 * Backend copies the row server-side so the unmasked secret never
 * crosses the wire.
 *
 * Permission: caller must be a member of the project (any role).
 */
export function useImportUserChannelFromProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      project_slug: string;
      channel_id: string;
      name?: string;
    }) =>
      api.post<UserChannel>(`/user/channels/import_from_project`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["user-channels"] });
    },
  });
}

export function useUpdateUserChannel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: UpdateUserChannelRequest }) =>
      api.patch<UserChannel>(`/user/channels/${id}`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["user-channels"] });
    },
  });
}

export function useDeleteUserChannel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.delete<void>(`/user/channels/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["user-channels"] });
      qc.invalidateQueries({ queryKey: ["user-subscriptions"] });
    },
  });
}

/**
 * Dispatch a test notification against an **unsaved** user-channel
 * config. Mirrors ``useTestChannelConfig`` for parity between the
 * per-project Providers page and the global settings/channels page.
 */
export function useTestUserChannelConfig() {
  return useMutation({
    mutationFn: (body: { type: ChannelType; config: Record<string, unknown> }) =>
      api.post<ChannelTestResult>(`/user/channels/test`, body),
  });
}

/**
 * Dispatch a test notification against an already-saved user channel.
 * Uses the channel's stored (unmasked) config.
 */
export function useTestUserChannel() {
  return useMutation({
    mutationFn: (channelId: string) =>
      api.post<ChannelTestResult>(`/user/channels/${channelId}/test`, {}),
  });
}

// ---------------------------------------------------------------------------
// User subscriptions
// ---------------------------------------------------------------------------

export function useUserSubscriptions(projectId?: string) {
  // v1.1.0: GET /user/subscriptions now returns
  // ``{items, next_cursor}``. The hook flattens to the legacy
  // array shape so existing call sites keep working; pagination
  // is followed transparently by walking ``next_cursor``.
  return useQuery<UserSubscription[]>({
    queryKey: ["user-subscriptions", projectId ?? "all"],
    queryFn: async () => {
      const items: UserSubscription[] = [];
      let cursor: string | null = null;
      do {
        const params = new URLSearchParams();
        if (projectId) params.set("project_id", projectId);
        params.set("limit", "500");
        if (cursor) params.set("cursor", cursor);
        const page = await api.get<{
          items: UserSubscription[];
          next_cursor: string | null;
        }>(`/user/subscriptions?${params.toString()}`);
        items.push(...page.items);
        cursor = page.next_cursor;
      } while (cursor);
      return items;
    },
  });
}

export function useCreateUserSubscription() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateSubscriptionRequest) =>
      api.post<UserSubscription>(`/user/subscriptions`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["user-subscriptions"] });
    },
  });
}

export function useUpdateUserSubscription() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      body,
    }: {
      id: string;
      body: UpdateSubscriptionRequest;
    }) => api.patch<UserSubscription>(`/user/subscriptions/${id}`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["user-subscriptions"] });
    },
  });
}

export function useDeleteUserSubscription() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.delete<void>(`/user/subscriptions/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["user-subscriptions"] });
    },
  });
}

// ---------------------------------------------------------------------------
// User notifications (the in-app bell)
// ---------------------------------------------------------------------------

export function useUserNotifications(opts?: {
  unreadOnly?: boolean;
  limit?: number;
}) {
  const params = new URLSearchParams();
  if (opts?.unreadOnly) params.set("unread_only", "true");
  if (opts?.limit) params.set("limit", String(opts.limit));
  const qs = params.toString();
  return useQuery<UserNotification[]>({
    queryKey: [
      "user-notifications",
      opts?.unreadOnly ?? false,
      opts?.limit ?? 50,
    ],
    queryFn: () =>
      api.get<UserNotification[]>(
        qs ? `/user/notifications?${qs}` : `/user/notifications`,
      ),
    refetchInterval: 30_000,
    staleTime: 15_000,
  });
}

export function useUnreadCount() {
  return useQuery<{ unread: number }>({
    queryKey: ["user-notifications-unread-count"],
    queryFn: () =>
      api.get<{ unread: number }>(`/user/notifications/unread-count`),
    refetchInterval: 30_000,
    staleTime: 15_000,
  });
}

export function useMarkRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.post<void>(`/user/notifications/${id}/read`, {}),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["user-notifications"] });
      qc.invalidateQueries({ queryKey: ["user-notifications-unread-count"] });
    },
  });
}

export function useMarkAllRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<void>(`/user/notifications/read-all`, {}),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["user-notifications"] });
      qc.invalidateQueries({ queryKey: ["user-notifications-unread-count"] });
    },
  });
}

// ---------------------------------------------------------------------------
// Project default subscriptions (admin)
// ---------------------------------------------------------------------------

export function useDefaultSubscriptions(slug: string) {
  return useQuery<ProjectDefaultSubscription[]>({
    queryKey: ["project-default-subscriptions", slug],
    queryFn: () =>
      api.get<ProjectDefaultSubscription[]>(
        `/projects/${slug}/notifications/defaults`,
      ),
    enabled: !!slug,
  });
}

export function useCreateDefaultSubscription(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateDefaultSubscriptionRequest) =>
      api.post<ProjectDefaultSubscription>(
        `/projects/${slug}/notifications/defaults`,
        body,
      ),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["project-default-subscriptions", slug],
      });
    },
  });
}

export function useUpdateDefaultSubscription(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      body,
    }: {
      id: string;
      body: UpdateDefaultSubscriptionRequest;
    }) =>
      api.patch<ProjectDefaultSubscription>(
        `/projects/${slug}/notifications/defaults/${id}`,
        body,
      ),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["project-default-subscriptions", slug],
      });
    },
  });
}

export function useDeleteDefaultSubscription(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.delete<void>(`/projects/${slug}/notifications/defaults/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["project-default-subscriptions", slug],
      });
    },
  });
}

// ---------------------------------------------------------------------------
// Delivery audit log (admin-only)
// ---------------------------------------------------------------------------

/** Paged delivery list envelope - matches DeliveryListPublic on the
 *  backend (POL-2). The dashboard still exposes the raw item array
 *  via ``data.items`` so existing callers can migrate incrementally. */
export interface NotificationDeliveryList {
  items: NotificationDelivery[];
  next_cursor: string | null;
}

export function useDeliveries(slug: string, limit = 50, cursor?: string | null) {
  return useQuery<NotificationDeliveryList>({
    queryKey: ["notification-deliveries", slug, limit, cursor ?? null],
    queryFn: () => {
      const params: Record<string, string | number> = { limit };
      if (cursor) params.cursor = cursor;
      return api.get<NotificationDeliveryList>(
        `/projects/${slug}/notifications/deliveries`,
        params,
      );
    },
    enabled: !!slug,
    staleTime: 30_000,
  });
}

/**
 * Personal delivery history across all the user's projects (v1.0.18).
 * Mirror of `useDeliveries` but unscoped, joins to the user's
 * personal subscriptions on the backend. Optional `projectSlug`
 * narrows the view to one project; deliveries from projects the
 * user is no longer a member of still surface (audit data outlives
 * membership). The dashboard renders those rows with a "you left
 * this project" hint by checking against the membership list.
 */
export function useUserDeliveries(
  limit = 50,
  cursor?: string | null,
  projectSlug?: string | null,
) {
  return useQuery<NotificationDeliveryList>({
    queryKey: [
      "user-deliveries",
      limit,
      cursor ?? null,
      projectSlug ?? null,
    ],
    queryFn: () => {
      const params: Record<string, string | number> = { limit };
      if (cursor) params.cursor = cursor;
      if (projectSlug) params.project_slug = projectSlug;
      return api.get<NotificationDeliveryList>(`/user/deliveries`, params);
    },
    staleTime: 30_000,
  });
}

/**
 * Bulk-delete every delivery row for the project (admin only).
 * Returns the number of rows deleted so the UI can confirm.
 */
export function useClearDeliveries(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api.delete<{ deleted: number }>(
        `/projects/${slug}/notifications/deliveries`,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notification-deliveries", slug] });
    },
  });
}

