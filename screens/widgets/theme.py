"""SecureOps design tokens — the single source of truth for the UI.

v3 — "Graphite" theme. A clean, professional black-and-white system: white
surfaces, near-black text, a single graphite accent, flat/minimal depth
(hairline borders, whisper shadows — no glows, gradients or heavy morphism).
Severity colours (red/orange/amber/blue) are preserved — they are functional
signal in a security tool, not decoration.

Everything is centralized and swappable. Existing token NAMES are preserved
(BG, CARD, ACCENT, TXT, SEVERITY_COLORS, spacing/radius/type scales, overline(),
the GLASS_*/NEU_*/CLAY_* families) so the global QSS and the whole widget tree
re-skin by changing values here. The morphism widget library reads these too;
in this theme every surface resolves to a flat white card.
"""

# ── Core palette — graphite on white ─────────────────────────────────────────
BG       = "#F7F7F9"   # App base — near-white
BG_ALT   = "#EFEFF2"   # Subtle alternating / sunken surface
CARD     = "#FFFFFF"   # Card / panel surface
INPUT    = "#FFFFFF"   # Input field background
HOVER    = "#F0F0F3"   # Neutral hover fill

ACCENT   = "#18181B"   # Primary accent — graphite (buttons, active, headers)
ACCENT_H = "#2E2E33"   # Lighter graphite — hover
ACCENT_D = "#0A0A0C"   # Near-black — pressed
ACCENT_SOFT = "#ECECEF"  # Tinted grey background (selected rows, chips)
ACCENT_GLOW = "#18181B"  # (kept for API compat — no glow in this theme)

WARM     = "#111114"   # Secondary emphasis (kept neutral)

TXT      = "#111114"   # Primary text — near-black
TXT2     = "#3F3F46"   # Secondary text
TXT3     = "#71717A"   # Muted text — WCAG-AA on white
BORDER   = "#E4E4E7"   # Default hairline border
BORDER_STRONG = "#D4D4D8"  # Emphasised border
FOCUS    = "#18181B"   # Focus ring — graphite

# Severity / status — professional, legible on white; preserved hues
CRITICAL = "#DC2626"
HIGH     = "#EA580C"
MEDIUM   = "#D97706"
LOW      = "#2563EB"
INFO     = "#6B7280"
SUCCESS  = "#16A34A"
WARNING  = "#D97706"

# Terminal / code surfaces (consoles read best dark — the one dark element)
TERMINAL_BG  = "#0E0E11"
TERMINAL_TXT = "#E4E4E7"

SEVERITY_COLORS = {
    "critical": CRITICAL,
    "high":     HIGH,
    "medium":   MEDIUM,
    "low":      LOW,
    "info":     INFO,
}

# ── Spacing scale (px, 4-pt grid) ─────────────────────────────────────────────
SP_XS = 4
SP_SM = 8
SP_MD = 12
SP_LG = 16
SP_XL = 24
SP_2XL = 32

# ── Radii ─────────────────────────────────────────────────────────────────────
RADIUS_SM = 6
RADIUS_MD = 8
RADIUS_LG = 10
RADIUS_CLAY = 10   # kept name; flat card corner
RADIUS_PILL = 999

# ── Type scale (px) ─────────────────────────────────────────────────────────────
FS_DISPLAY = 22   # Page titles
FS_TITLE   = 16   # Section / panel titles
FS_SUBTITLE = 13  # Sub-headers
FS_BODY    = 12   # Body
FS_SMALL   = 11   # Captions / metadata
FS_TINY    = 10   # Labels / overlines

FONT_SANS = '"Inter", "DM Sans", "Segoe UI", sans-serif'
FONT_MONO = '"JetBrains Mono", "Space Mono", "DejaVu Sans Mono", monospace'

# ── Root background (near-flat, barely-there light gradient) ──────────────────
MESH_STOPS = [
    (0.0, "#FFFFFF"),
    (0.55, "#F7F7F9"),
    (1.0, "#F1F1F4"),
]
MESH_BLOOM = "#FFFFFF"   # no coloured bloom in this theme

# ── Glass family (now: flat white surfaces + hairline) ───────────────────────
GLASS_FILL        = "#FFFFFF"
GLASS_FILL_STRONG = "#FFFFFF"
GLASS_EDGE        = "rgba(255, 255, 255, 0.0)"
GLASS_EDGE_SOFT   = "rgba(255, 255, 255, 0.0)"
GLASS_HAIRLINE    = "#E4E4E7"


def glass_fill(alpha: float = 1.0) -> str:
    return f"rgba(255, 255, 255, {alpha})"


# ── Neu family (now: flat controls) ──────────────────────────────────────────
NEU_BASE      = "#FFFFFF"
NEU_BASE_HI   = "#FFFFFF"
NEU_BASE_LO   = "#F0F0F3"
NEU_LIGHT     = (255, 255, 255, 0)
NEU_DARK      = (17, 17, 20, 0)
NEU_INSET_DARK  = (17, 17, 20, 0)
NEU_INSET_LIGHT = (255, 255, 255, 0)

# ── Clay family (now: flat cards) ────────────────────────────────────────────
CLAY_FILL_TOP    = "#FFFFFF"
CLAY_FILL_BOT    = "#FFFFFF"
CLAY_INNER_HI    = "rgba(255, 255, 255, 0.0)"

# ── Status LED (skeuomorphic; hexes asserted by tests) ───────────────────────
LED_GREEN = "#00ff88"
LED_AMBER = "#ffaa00"
LED_RED   = "#ff4444"

# ── Elevation / shadow presets — flat & minimal (whisper only) ───────────────
# (blur_radius, dx, dy, (r, g, b, a)) — consumed by QGraphicsDropShadowEffect.
ELEVATION = {
    "flat":  (0,  0, 0, (0, 0, 0, 0)),
    "glass": (14, 0, 3, (17, 17, 20, 18)),     # whisper card lift
    "clay":  (14, 0, 3, (17, 17, 20, 18)),
    "raise": (20, 0, 6, (17, 17, 20, 30)),     # hover lift
    "glow":  (0,  0, 0, (0, 0, 0, 0)),
}


def elevation(name: str):
    return ELEVATION.get(name, ELEVATION["flat"])


def overline(text_color: str = TXT3, size: int = FS_TINY) -> str:
    """QSS snippet for an uppercase overline/section label."""
    return (
        f"color: {text_color}; font-size: {size}px; font-weight: bold; "
        "letter-spacing: 1px;"
    )
