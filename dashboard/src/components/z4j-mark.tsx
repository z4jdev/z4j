/**
 * z4j brand mark - the hexagon-with-Z logo.
 *
 * Renders as a single-color SVG using `currentColor` so it inherits
 * from the parent's text color (e.g. `text-primary-foreground` on a
 * primary tile, or `text-primary` on a transparent surface).
 */
export function Z4jMark({ className }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 512 512"
      className={className}
      aria-hidden="true"
    >
      <path
        d="M 256 66 L 420.545 161 L 420.545 351 L 256 446 L 91.455 351 L 91.455 161 Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="40"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M 162 175 H 350 L 162 337 H 350"
        fill="none"
        stroke="currentColor"
        strokeWidth="40"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="162" cy="175" r="26" fill="currentColor" />
      <circle cx="350" cy="337" r="26" fill="currentColor" />
    </svg>
  );
}
