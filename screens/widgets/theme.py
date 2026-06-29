"""SecureOps design tokens — the single source of truth for the UI.

Light, modern, corporate palette. Every screen and widget pulls colours,
spacing, radii and type sizes from here; nothing should hardcode a hex value.
Backwards-compatible names (BG, CARD, ACCENT, …) are preserved so existing
imports keep working.
"""

# ── Palette ─────────────────────────────────────────────────────────────────
BG       = "#F4F6F9"   # App background — cool white
BG_ALT   = "#EDF1F7"   # Subtle alternating / sunken surface
CARD     = "#FFFFFF"   # Card / panel surface
INPUT    = "#EEF1F6"   # Input field background
HOVER    = "#E4EAF2"   # Neutral hover fill

ACCENT   = "#3D5A80"   # Primary accent — slate blue
ACCENT_H = "#5C7FA8"   # Lighter slate — hover
ACCENT_D = "#2C4360"   # Darker slate — pressed
ACCENT_SOFT = "#E2E9F2"  # Tinted accent background (selected rows, chips)

TXT      = "#1A202C"   # Primary text — near-black
TXT2     = "#3F4A5A"   # Secondary text (darkened for contrast)
TXT3     = "#64748B"   # Muted text — slate 500, WCAG-AA on BG/CARD
BORDER   = "#D1D9E6"   # Default border
BORDER_STRONG = "#B8C3D4"  # Emphasised border

FOCUS    = "#2B6CB0"   # Focus ring — accessible blue

# Severity / status
CRITICAL = "#E53E3E"
HIGH     = "#DD6B20"
MEDIUM   = "#D69E2E"
LOW      = "#3D5A80"
INFO     = "#4A5568"
SUCCESS  = "#2F855A"
WARNING  = "#D69E2E"

# Terminal / code surfaces (kept dark for legibility of streaming output)
TERMINAL_BG = "#0F1729"
TERMINAL_TXT = "#CBD5E1"

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
RADIUS_SM = 4
RADIUS_MD = 8
RADIUS_LG = 12
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


def overline(text_color: str = TXT3, size: int = FS_TINY) -> str:
    """QSS snippet for an uppercase overline/section label."""
    return (
        f"color: {text_color}; font-size: {size}px; font-weight: bold; "
        "letter-spacing: 1px;"
    )
