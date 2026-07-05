# SecureOps — Style Guide

**Theme:** "Graphite" — a clean, professional black-and-white system. White
surfaces, near-black text, a single **graphite `#18181B`** accent, and flat/
minimal depth (hairline borders + whisper shadows — no glows, gradients or
heavy morphism). The morphism widget library is retained but flattened: every
surface resolves to a flat white card, controls to bordered flat fills. The one
dark element is the terminal/console. Severity colours (red/orange/amber/blue)
are preserved — functional signal, not decoration.

Everything is centralized in `screens/widgets/theme.py` and built into reusable
components in `screens/widgets/morphism.py`. Change tokens in one place → the
whole app re-skins.

---

## 1. Each morphism has ONE semantic role

| Morphism | Role | Where it's used | Components |
|----------|------|-----------------|------------|
| **Glassmorphism** | Structure & surfaces | Title bar, sidebar, content panels, cards, tables, status bar | `GlassPanel`, `GlassCard`, `TitleBar`, `#card`/`#panel`/`#sidebar` QSS |
| **Neumorphism** | Interactive controls | Scan mode toggles (Scan Target / Scan IP / Analyse Logs), inset text fields | `NeuButton`, `NeuLineEdit` |
| **Claymorphism** | Key data callouts | Dashboard stat tiles, severity cards, badges/pills | `ClayStatTile` (= `StatCard`), `ClaySeverityCard`, `SeverityBadge`, `Badge` |
| **Skeuomorphism** | Literal / physical | LIVE OUTPUT terminal, toggle switches, status LED, padlock brand, mesh background | `TerminalOutput`, `ToggleSwitch`, `StatusLED`, `TitleBar` brand, `RootBackground` |

Do **not** mix roles (e.g. don't make a primary button glassy or a panel clay).

---

## 2. QSS reality (why these are painted, not styled)

Qt Style Sheets silently ignore `backdrop-filter` and `box-shadow`, and
`QGraphicsDropShadowEffect` draws only a **single** outer shadow (no inset,
no dual). So:

- **Glass** — no real blur. Approximated with: a mesh gradient painted on
  `RootBackground` (`paintEvent`), semi-transparent rgba panel fills
  (`GLASS_FILL` ~55%), a 1px bright top/left edge (painted in `GlassPanel`),
  and one shared soft `QGraphicsDropShadowEffect` (`elevation("glass")`).
  *Upgrade path for true live blur: move a panel to QML + `MultiEffect`/`FastBlur`.*
- **Neumorphism** — needs dual shadows + inset. Implemented in `paint_neu()`
  with `QPainter`: layered translucent rounded rects fake a Gaussian blur
  (light top-left + dark bottom-right); pressed/checked state paints an inner
  inset instead. `_NEU_MARGIN` reserves room inside the widget for the shadows.
- **Claymorphism** — `_paint_clay()`: large corner radius (`RADIUS_CLAY`),
  a soft *coloured* drop shadow tinted by the tile accent, a vertical gradient
  body, and a faint inner top highlight.
- **Skeuomorphism** — fully painted: terminal scanline overlay
  (`_Scanlines`), glowing LED (`StatusLED` + colored blur), sliding
  `ToggleSwitch` with an "on" glow, padlock brand with a violet halo.

**Performance:** reuse the `ELEVATION` presets via `apply_elevation()`; never
hand-tune a fresh shadow per child. For high-count lists (threat feed, finding
cards) prefer painted depth over stacking `QGraphicsDropShadowEffect`s.

---

## 3. Token reference (`theme.py`)

**Base:** `BG #F7F7F9` · `BG_ALT` · `CARD #FFFFFF` · `INPUT` · `HOVER`
**Accent (Graphite family):** `ACCENT #18181B` · `ACCENT_H #2E2E33` · `ACCENT_D #0A0A0C` ·
`ACCENT_SOFT #ECECEF` · `ACCENT_GLOW` (compat, no glow) · `WARM`
**Text:** `TXT #111114` · `TXT2` · `TXT3` (all WCAG-AA on BG/CARD) · `BORDER` · `BORDER_STRONG` · `FOCUS`
**Severity (preserved):** `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `INFO` · `SUCCESS`
**Glass:** `GLASS_FILL`, `GLASS_FILL_STRONG`, `GLASS_EDGE`, `GLASS_HAIRLINE`, `glass_fill(alpha)`
**Neu:** `NEU_BASE`, `NEU_BASE_HI`, `NEU_LIGHT`, `NEU_DARK`, `NEU_INSET_*`
**Clay:** `CLAY_FILL_TOP`, `CLAY_FILL_BOT`, `CLAY_INNER_HI`, `RADIUS_CLAY`
**Skeu:** `LED_GREEN/AMBER/RED`, `TERMINAL_BG`, `TERMINAL_TXT`, `MESH_STOPS`, `MESH_BLOOM`
**Scales:** `SP_*` (4pt grid) · `RADIUS_SM/MD/LG/CLAY/PILL` · `FS_*` · `FONT_SANS/MONO`
**Elevation presets:** `ELEVATION["glass"|"clay"|"raise"|"glow"|"flat"]` → `elevation(name)`

---

## 4. Micro-interactions

- **Neu press** → inset (checked/`isDown()` repaints via `paint_neu(pressed=True)`).
- **Glass hover** → raise shadow (`elevation("raise")`) + brighter edge.
- **Clay counts** → animate via `QVariantAnimation` (count-up) + a share bar.
- **Toggle / LED** → animated knob slide + colored glow.
- Elevation changes animate with `QPropertyAnimation` where used.

---

## 5. Accessibility

Neumorphism is low-contrast by nature — body text is **never** placed on a
neu fill. Button/label text uses `TXT`/`TXT2`/`ACCENT_H` which meet WCAG AA on
the dark base. `LOW`/`INFO` severity blues were brightened for dark legibility.

---

## 6. Using the library

```python
from screens.widgets.morphism import (
    GlassPanel, GlassCard, NeuButton, NeuLineEdit,
    ClayStatTile, ClaySeverityCard, SeverityBadge,
    TerminalOutput, ToggleSwitch, StatusLED, TitleBar,
    RootBackground, apply_elevation,
)
```

Compose every screen from these so spacing, depth and morphism roles stay
consistent. New screens should use `GlassCard` for panels, `NeuButton`/
`NeuLineEdit` for controls, `ClayStatTile`/`ClaySeverityCard`/`SeverityBadge`
for data callouts, and `TerminalOutput`/`ToggleSwitch`/`StatusLED` for
physical elements.
