/** The guided editor only accepts shapes it can round-trip without data loss. */
export const CONDITION_FIELDS = [
  ["engine", "Engine equals"],
  ["queue", "Queue equals"],
  ["task_name", "Task name contains"],
  ["exception", "Exception contains"],
  ["fingerprint", "Issue fingerprint equals"],
] as const;
export type GuidedConditions = Record<string, string>;
export function guidedConditions(text: string): GuidedConditions | null {
  try {
    const value: unknown = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value))
      return null;
    if (
      !Object.entries(value).every(
        ([key, v]) =>
          CONDITION_FIELDS.some(([field]) => field === key) &&
          typeof v === "string",
      )
    )
      return null;
    return value as GuidedConditions;
  } catch {
    return null;
  }
}
export function guidedAction(text: string): string | null {
  try {
    const value: unknown = JSON.parse(text);
    if (!Array.isArray(value) || value.length !== 1) return null;
    const action = value[0];
    if (
      !action ||
      typeof action !== "object" ||
      Object.keys(action).length !== 1 ||
      !["notify", "retry", "cancel"].includes(action.type)
    )
      return null;
    return action.type;
  } catch {
    return null;
  }
}
