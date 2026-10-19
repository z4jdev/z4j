/** Accept only rooted paths that the browser resolves on the same origin. */
export function isSafeNextPath(raw: string | undefined): raw is string {
  if (!raw?.startsWith("/")) return false;
  if (raw.startsWith("//") || raw.startsWith("/\\")) return false;
  // Browsers strip some ASCII whitespace before interpreting URL authority.
  // Reject it before parsing so `/\t/other.example` cannot become `//...`.
  if (Array.from(raw).some((char) => char.charCodeAt(0) <= 32 || char.charCodeAt(0) === 127)) {
    return false;
  }
  const base = "https://z4j.invalid";
  try {
    return new URL(raw, base).origin === base;
  } catch {
    return false;
  }
}
