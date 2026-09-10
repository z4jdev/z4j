/** Palette names and preference migration. Color values live in the CSS tokens. */
export const PALETTES = [
  {
    id: "sapphire",
    name: "Sapphire",
    description: "Clear blue with white and graphite neutrals.",
  },
  {
    id: "jade",
    name: "Jade",
    description: "Deep teal with white and graphite neutrals.",
  },
  {
    id: "iris",
    name: "Iris",
    description: "Balanced indigo with white and graphite neutrals.",
  },
  {
    id: "sandstone",
    name: "Sandstone",
    description: "Warm bronze with white and graphite neutrals.",
  },
] as const;

export type PaletteId = (typeof PALETTES)[number]["id"];
export const DEFAULT_PALETTE: PaletteId = "sapphire";
export const PALETTE_STORAGE_KEY = "z4j-palette";

export function isPalette(value: unknown): value is PaletteId {
  return PALETTES.some((palette) => palette.id === value);
}

/** Mirrors the tiny pre-paint bootstrap; parity is checked against index.html. */
export function resolvePalette(
  value: unknown,
  legacyHue: string | null,
): PaletteId {
  if (isPalette(value)) return value;
  const legacy: Record<string, PaletteId> = {
    "250": "sapphire",
    "280": "iris",
    "310": "iris",
    "350": "sandstone",
    "25": "sandstone",
    "50": "sandstone",
    "150": "jade",
    "180": "jade",
    "210": "sapphire",
  };
  return legacyHue !== null && Object.hasOwn(legacy, legacyHue)
    ? legacy[legacyHue]
    : DEFAULT_PALETTE;
}

export function readStoredPalette(): PaletteId {
  try {
    return resolvePalette(
      window.localStorage.getItem(PALETTE_STORAGE_KEY),
      window.localStorage.getItem("z4j-primary-hue"),
    );
  } catch {
    return DEFAULT_PALETTE;
  }
}
