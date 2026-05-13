/**
 * MFA / TOTP hooks.
 *
 * Backs:
 *   - Login second step (POST /auth/mfa/verify)
 *   - Settings > Security tab (enroll, status, disable, regenerate)
 *   - Trusted devices list and revoke
 *
 * Mirrors the backend routes shipped in z4j 1.6.0; see
 * docs/MFA-DESIGN.md for the design.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

export interface MfaStatusResponse {
  enrolled: boolean;
  enrolled_at: string | null;
  remaining_recovery_codes: number;
}

export interface EnrollStartResponse {
  secret_base32: string;
  provisioning_url: string;
}

export interface EnrollCompleteResponse {
  recovery_codes: string[];
}

export interface VerifyResponse {
  ok: boolean;
  used_recovery_code: boolean;
  remaining_recovery_codes: number | null;
}

export interface TrustedDevicePublic {
  id: string;
  label: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  revoked_at: string | null;
  is_current: boolean;
}

const MFA_STATUS_KEY = ["auth", "mfa", "status"] as const;
const MFA_DEVICES_KEY = ["auth", "mfa", "trusted-devices"] as const;

export function useMfaStatus(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: MFA_STATUS_KEY,
    queryFn: () => api.get<MfaStatusResponse>("/auth/mfa/status"),
    staleTime: 30_000,
    enabled: options?.enabled ?? true,
  });
}

export function useEnrollStart() {
  return useMutation({
    mutationFn: () =>
      api.post<EnrollStartResponse>("/auth/mfa/enroll-start", {}),
  });
}

export function useEnrollComplete() {
  // Intentionally does NOT invalidate the MFA status query on success.
  // The enrollment UI needs to stay on the "show recovery codes" step
  // until the user acknowledges they have saved them, and the parent
  // component picks between "enroll" and "enrolled" panels purely
  // from the status cache. If we invalidated here, the cache would
  // flip to enrolled=true before the recovery codes ever rendered and
  // the user would land on the "MFA is on" panel having never seen
  // (or downloaded) their one-time codes -- which is the precise
  // disaster MFA recovery codes are supposed to prevent. The user
  // clicks "Done" on the RecoveryCodesPanel, which reloads the page
  // and picks up the fresh status naturally.
  return useMutation({
    mutationFn: (body: { code: string }) =>
      api.post<EnrollCompleteResponse>("/auth/mfa/enroll-complete", body),
  });
}

export function useMfaVerify() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { code: string; remember_device?: boolean }) =>
      api.post<VerifyResponse>("/auth/mfa/verify", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: MFA_STATUS_KEY });
      qc.invalidateQueries({ queryKey: MFA_DEVICES_KEY });
    },
  });
}

export function useMfaDisable() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { password: string; code: string }) =>
      api.post<VerifyResponse>("/auth/mfa/disable", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: MFA_STATUS_KEY });
      qc.invalidateQueries({ queryKey: MFA_DEVICES_KEY });
    },
  });
}

export function useRegenerateRecoveryCodes() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api.post<{ recovery_codes: string[] }>(
        "/auth/mfa/recovery-codes/regenerate",
        {},
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: MFA_STATUS_KEY });
    },
  });
}

export function useTrustedDevices(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: MFA_DEVICES_KEY,
    queryFn: () =>
      api.get<TrustedDevicePublic[]>("/auth/mfa/trusted-devices"),
    enabled: options?.enabled ?? true,
  });
}

export function useRevokeTrustedDevice() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (deviceId: string) =>
      api.post<void>(
        `/auth/mfa/trusted-devices/${deviceId}/revoke`,
        {},
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: MFA_DEVICES_KEY });
    },
  });
}

export function useTrustCurrentDevice() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api.post<TrustedDevicePublic>("/auth/mfa/trusted-devices", {}),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: MFA_DEVICES_KEY });
    },
  });
}

export function useRenameTrustedDevice() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      deviceId,
      label,
    }: {
      deviceId: string;
      label: string;
    }) =>
      api.patch<TrustedDevicePublic>(
        `/auth/mfa/trusted-devices/${deviceId}`,
        { label },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: MFA_DEVICES_KEY });
    },
  });
}
