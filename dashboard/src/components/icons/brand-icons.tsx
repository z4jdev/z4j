/**
 * Brand SVG icons for notification channel types.
 *
 * Inline SVGs (paths from simple-icons.org, MIT-licensed) so we
 * avoid pulling in a 1MB+ icon package just for four logos.
 *
 * Each component takes the same prop shape as a lucide icon
 * (className, size) so they slot directly into the
 * CHANNEL_ICONS dictionaries without shimming.
 *
 * The original brand colors are preserved in the SVG paths via
 * `fill="currentColor"` defaults so they tint with the surrounding
 * Tailwind text color (e.g. text-muted-foreground in the channel
 * card icon slot). For the brand-accurate multi-color variants
 * (Slack's 4-color hashtag, Discord's purple, etc.) wrap with the
 * `colored` prop.
 */
import * as React from "react";

interface IconProps extends React.SVGAttributes<SVGElement> {
  size?: number | string;
  /**
   * When true, render the icon in its brand colors instead of
   * inheriting the surrounding text color. Default false so icons
   * blend into card/header neutrals.
   */
  colored?: boolean;
}

function svgProps(size: number | string = 16) {
  return {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    xmlns: "http://www.w3.org/2000/svg",
    role: "img" as const,
    "aria-hidden": "true" as const,
  };
}

export function SlackIcon({
  size = 16,
  className,
  colored = false,
}: IconProps) {
  // Slack's 4-color hashtag - 8 rounded rects.
  const fill = colored ? undefined : "currentColor";
  return (
    <svg {...svgProps(size)} className={className} fill={fill}>
      <path
        d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313z"
        fill={colored ? "#E01E5A" : undefined}
      />
      <path
        d="M8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312z"
        fill={colored ? "#36C5F0" : undefined}
      />
      <path
        d="M18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312z"
        fill={colored ? "#2EB67D" : undefined}
      />
      <path
        d="M15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"
        fill={colored ? "#ECB22E" : undefined}
      />
    </svg>
  );
}

export function TelegramIcon({
  size = 16,
  className,
  colored = false,
}: IconProps) {
  // Telegram's blue circle + paper plane.
  return (
    <svg
      {...svgProps(size)}
      className={className}
      fill={colored ? undefined : "currentColor"}
    >
      <path
        d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"
        fill={colored ? "#26A5E4" : undefined}
      />
    </svg>
  );
}

export function DiscordIcon({
  size = 16,
  className,
  colored = false,
}: IconProps) {
  // Discord's speech-bubble gamepad.
  return (
    <svg
      {...svgProps(size)}
      className={className}
      fill={colored ? undefined : "currentColor"}
    >
      <path
        d="M20.317 4.37a19.79 19.79 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.74 19.74 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.058a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.84 19.84 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.955 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418Z"
        fill={colored ? "#5865F2" : undefined}
      />
    </svg>
  );
}

export function PagerDutyIcon({
  size = 16,
  className,
  colored = false,
}: IconProps) {
  // PagerDuty's stylized "P" - flat block with bottom rectangle.
  return (
    <svg
      {...svgProps(size)}
      className={className}
      fill={colored ? undefined : "currentColor"}
    >
      <path
        d="M16.965 1.18C15.085.164 13.769 0 10.683 0H3.73v14.55h6.926c2.743 0 4.8-.164 6.61-1.37 1.975-1.288 3.072-3.43 3.072-6.005 0-2.66-1.234-4.797-3.374-5.996zm-3.292 9.708c-.987.575-2.027.685-3.949.685H7.198V3.595h2.6c1.756 0 2.99.137 3.95.713 1.563.93 2.357 2.494 2.357 4.252 0 1.84-.794 3.404-2.43 4.328zM3.73 17.252h3.468V24H3.73Z"
        fill={colored ? "#06AC38" : undefined}
      />
    </svg>
  );
}
