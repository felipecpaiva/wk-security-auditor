---
name: Wolters Kluwer Security Auditor
colors:
  surface: "#f8f9fa"
  surface-dim: "#e9ecef"
  surface-bright: "#ffffff"
  surface-container-lowest: "#ffffff"
  surface-container-low: "#f1f3f5"
  surface-container: "#e9ecef"
  surface-container-high: "#dee2e6"
  surface-container-highest: "#ced4da"
  on-surface: "#212529"
  on-surface-variant: "#495057"
  inverse-surface: "#1a2332"
  inverse-on-surface: "#f8f9fa"
  outline: "#adb5bd"
  outline-variant: "#dee2e6"
  primary: "#007ac3"
  on-primary: "#ffffff"
  primary-container: "#d6eeff"
  on-primary-container: "#004a75"
  secondary: "#6db33f"
  on-secondary: "#ffffff"
  secondary-container: "#e8f5e0"
  on-secondary-container: "#3d6b1f"
  tertiary: "#8bc53f"
  on-tertiary: "#ffffff"
  tertiary-container: "#edf7df"
  on-tertiary-container: "#4a6b22"
  error: "#e31937"
  on-error: "#ffffff"
  error-container: "#fce4e8"
  on-error-container: "#8c0f22"
  warning: "#f5a623"
  on-warning: "#ffffff"
  warning-container: "#fff3e0"
  success: "#6db33f"
  on-success: "#ffffff"
  success-container: "#e8f5e0"
  severity-critical: "#e31937"
  severity-high: "#f5a623"
  severity-medium: "#f5c623"
  severity-low: "#6db33f"
  severity-critical-bg: "rgba(227, 25, 55, 0.1)"
  severity-high-bg: "rgba(245, 166, 35, 0.1)"
  severity-medium-bg: "rgba(245, 198, 35, 0.1)"
  severity-low-bg: "rgba(109, 179, 63, 0.1)"
  brand-blue-dark: "#004a75"
  brand-blue: "#007ac3"
  brand-blue-light: "#a8d5e8"
  brand-green-dark: "#3d6b1f"
  brand-green: "#6db33f"
  brand-green-bright: "#8bc53f"
  brand-lime: "#c4d82e"
  brand-red: "#e31937"
  brand-gray: "#4a4f54"
  header-gradient-start: "#004a75"
  header-gradient-end: "#007ac3"
  background: "#f8f9fa"
  on-background: "#212529"
typography:
  display-lg:
    fontFamily: "'Fira Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    fontSize: 56px
    fontWeight: "300"
    lineHeight: 64px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: "'Fira Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    fontSize: 28px
    fontWeight: "600"
    lineHeight: 36px
    letterSpacing: -0.01em
  headline-md:
    fontFamily: "'Fira Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    fontSize: 20px
    fontWeight: "600"
    lineHeight: 28px
  body-lg:
    fontFamily: "'Fira Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    fontSize: 16px
    fontWeight: "400"
    lineHeight: 24px
  body-md:
    fontFamily: "'Fira Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    fontSize: 14px
    fontWeight: "400"
    lineHeight: 20px
  body-sm:
    fontFamily: "'Fira Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    fontSize: 12px
    fontWeight: "400"
    lineHeight: 16px
  label-lg:
    fontFamily: "'Fira Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    fontSize: 14px
    fontWeight: "600"
    lineHeight: 20px
    letterSpacing: 0.01em
  label-sm:
    fontFamily: "'Fira Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    fontSize: 11px
    fontWeight: "600"
    lineHeight: 16px
    letterSpacing: 0.04em
    textTransform: uppercase
  mono:
    fontFamily: "'Fira Code', 'SF Mono', 'Cascadia Code', monospace"
    fontSize: 13px
    fontWeight: "400"
    lineHeight: 20px
spacing:
  unit: 8px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  xxl: 48px
  container-padding: 32px
  card-padding: 24px
  card-gap: 16px
  section-gap: 24px
  header-height: 64px
radii:
  sm: 4px
  md: 8px
  lg: 12px
  xl: 16px
  xxl: 24px
  full: 9999px
components:
  header:
    background: "linear-gradient(135deg, #004a75 0%, #007ac3 100%)"
    height: 64px
    borderBottom: "3px solid #6db33f"
    color: "#ffffff"
    titleFont: headline-md
    subtitleFont: body-md
    subtitleOpacity: 0.8
  stat-card:
    background: "#ffffff"
    borderRadius: 12px
    padding: 24px
    border: "1px solid #dee2e6"
    shadow: "0 1px 3px rgba(0, 0, 0, 0.08)"
    valueFont: display-lg
    labelFont: label-sm
  severity-badge:
    borderRadius: 4px
    padding: "2px 10px"
    font: label-sm
    variants:
      critical:
        background: "rgba(227, 25, 55, 0.1)"
        color: "#e31937"
      high:
        background: "rgba(245, 166, 35, 0.1)"
        color: "#f5a623"
      medium:
        background: "rgba(245, 198, 35, 0.1)"
        color: "#f5c623"
      low:
        background: "rgba(109, 179, 63, 0.1)"
        color: "#6db33f"
  upload-zone:
    background: "#f1f3f5"
    border: "2px dashed #adb5bd"
    borderRadius: 16px
    padding: 32px
    textAlign: center
    dragoverBorder: "2px dashed #007ac3"
    dragoverBackground: "#d6eeff"
  data-table:
    headerBackground: "#f1f3f5"
    headerFont: label-sm
    headerBorderBottom: "2px solid #dee2e6"
    cellFont: body-md
    cellPadding: "12px 16px"
    rowBorderBottom: "1px solid #dee2e6"
    hoverBackground: "#f1f3f5"
    ruleColumnFont: mono
    resourceColumnFont: mono
  chart:
    doughnut:
      cutout: "68%"
      borderWidth: 0
      legendPosition: bottom
      legendFont: label-lg
    line:
      tension: 0.3
      borderColor: "#007ac3"
      fillColor: "rgba(0, 122, 195, 0.08)"
      pointRadius: 5
      borderWidth: 2
      yMin: 0
      yMax: 100
      gridColor: "#dee2e6"
---

# Enterprise Security Guardrail Auditor — Design System

## Brand & Style

This design system implements the **Wolters Kluwer** corporate identity for the Security Guardrail Auditor dashboard. Colors are extracted from the WK globe logo and wordmark. The overall aesthetic is **professional, enterprise-grade, and light-themed** — matching WK's corporate web presence.

The WK globe logo features a mosaic of blues and greens. The small red square in the logo is reserved exclusively for **critical severity** indicators — it signals danger and demands attention.

**Brand voice:** Authoritative, clear, compliance-focused. No playful language. Labels use uppercase for formality.

## Colors

### Brand Palette

| Token | Hex | Usage |
|-------|-----|-------|
| `brand-blue-dark` | `#004a75` | Header gradient start, high-emphasis text |
| `brand-blue` | `#007ac3` | Primary actions, links, chart lines |
| `brand-blue-light` | `#a8d5e8` | Decorative accents |
| `brand-green` | `#6db33f` | Success states, header accent bar, secondary actions |
| `brand-green-bright` | `#8bc53f` | Tertiary accents |
| `brand-lime` | `#c4d82e` | Decorative only |
| `brand-red` | `#e31937` | Critical severity ONLY — never decorative |
| `brand-gray` | `#4a4f54` | Wordmark text, neutral emphasis |

### Surface System

Light theme with subtle layering for depth:

| Token | Hex | Usage |
|-------|-----|-------|
| `background` | `#f8f9fa` | Page background |
| `surface-bright` | `#ffffff` | Cards, modals, elevated content |
| `surface-container-low` | `#f1f3f5` | Table headers, upload zone, hover rows |
| `surface-container` | `#e9ecef` | Dimmed backgrounds |
| `surface-container-high` | `#dee2e6` | Borders, dividers |
| `outline` | `#adb5bd` | Subtle borders, dashed lines |
| `outline-variant` | `#dee2e6` | Card borders, table dividers |

### Severity Scale

Four-level scale for security findings. Each level has a solid color and a 10% opacity background variant:

| Level | Color | Background | Weight |
|-------|-------|------------|--------|
| Critical | `#e31937` | `rgba(227, 25, 55, 0.1)` | 10 |
| High | `#f5a623` | `rgba(245, 166, 35, 0.1)` | 7 |
| Medium | `#f5c623` | `rgba(245, 198, 35, 0.1)` | 4 |
| Low | `#6db33f` | `rgba(109, 179, 63, 0.1)` | 2 |

## Typography

Two font families — one for UI, one for code:

| Role | Family | Fallback Stack |
|------|--------|---------------|
| UI text | Fira Sans | -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif |
| Code / IDs | Fira Code | SF Mono, Cascadia Code, monospace |

### Type Scale

| Token | Size | Weight | Line Height | Letter Spacing | Usage |
|-------|------|--------|-------------|----------------|-------|
| `display-lg` | 56px | 300 | 64px | -0.02em | Hero numbers (risk score, stat values) |
| `headline-lg` | 28px | 600 | 36px | -0.01em | Page titles |
| `headline-md` | 20px | 600 | 28px | — | Section titles, card headers |
| `body-lg` | 16px | 400 | 24px | — | Upload zone text, prominent body |
| `body-md` | 14px | 400 | 20px | — | Default body text, table cells |
| `body-sm` | 12px | 400 | 16px | — | Hints, timestamps, metadata |
| `label-lg` | 14px | 600 | 20px | 0.01em | Button text, emphasis labels |
| `label-sm` | 11px | 600 | 16px | 0.04em | Table headers, stat labels (UPPERCASE) |
| `mono` | 13px | 400 | 20px | — | Rule IDs, resource names, code |

## Layout & Spacing

### Grid System

- **8px base unit** — all spacing is a multiple of 8px
- **Max container width:** 1400px, centered with `container-padding` (32px) on each side
- **Stats grid:** `auto-fit, minmax(200px, 1fr)` — responsive card layout
- **Charts grid:** 2-column at >=900px, stacks to 1-column below
- **Top grid:** 2-column (risk display + doughnut), stacks below 900px

### Spacing Tokens

| Token | Value | Usage |
|-------|-------|-------|
| `xs` | 4px | Tight spacing (badge padding, inline gaps) |
| `sm` | 8px | Between related elements |
| `md` | 16px | Standard content spacing |
| `lg` | 24px | Container padding, section margins |
| `xl` | 32px | Large container padding |
| `xxl` | 48px | Empty state padding |
| `card-padding` | 24px | Inside cards and elevated surfaces |
| `card-gap` | 16px | Between cards in a grid |
| `section-gap` | 24px | Between page sections |

## Elevation & Depth

Light, subtle shadows only. This is a data-heavy enterprise tool — depth serves hierarchy, not decoration.

| Level | Shadow | Usage |
|-------|--------|-------|
| Level 0 | none | Page background, flat surfaces |
| Level 1 | `0 1px 3px rgba(0, 0, 0, 0.08)` | Cards, tables, elevated panels |
| Level 2 | `0 2px 8px rgba(0, 0, 0, 0.12)` | Reserved for modals/dropdowns (future) |

No colored shadows. No blur effects. No glassmorphism.

## Shapes

| Token | Radius | Usage |
|-------|--------|-------|
| `sm` | 4px | Badges, small pills |
| `md` | 8px | Buttons, input fields |
| `lg` | 12px | Cards, table wrappers |
| `xl` | 16px | Upload zone, hero sections |
| `xxl` | 24px | Large decorative containers |
| `full` | 9999px | Circular indicators |

## Components

### Header

- **Background:** Linear gradient 135deg from `#004a75` to `#007ac3`
- **Height:** 64px
- **Border bottom:** 3px solid `#6db33f` (green accent bar — WK signature)
- **Title:** `headline-md` in white, left-aligned
- **Subtitle:** `body-md` in white at 80% opacity, right-aligned
- **Layout:** Flexbox, `space-between`, vertically centered

### Stat Card

- **Background:** `surface-bright` (#ffffff)
- **Border:** 1px solid `outline-variant`
- **Border radius:** `lg` (12px)
- **Shadow:** Level 1
- **Padding:** `card-padding` (24px)
- **Value:** `display-lg` (56px, weight 300). Color varies by context:
  - Default: `primary` (#007ac3)
  - Critical count: `severity-critical`
  - High count: `severity-high`
  - Medium count: `severity-medium`
  - Low count: `severity-low`
- **Label:** `label-sm` in `on-surface-variant`, uppercase

### Severity Badge

- **Border radius:** `sm` (4px)
- **Padding:** 2px 10px
- **Font:** `label-sm` (11px, weight 600, uppercase, 0.04em tracking)
- **Variants:** Four levels, each with colored text on tinted background (see Severity Scale)
- **Display:** inline-block

### Upload Zone

- **Background:** `surface-container-low` (#f1f3f5)
- **Border:** 2px dashed `outline` (#adb5bd)
- **Border radius:** `xl` (16px)
- **Padding:** `xl` (32px)
- **Text align:** center
- **Drag-over state:** Border becomes 2px dashed `primary`, background becomes `primary-container`
- **Button:** `label-lg` font, `primary` background, `on-primary` text, 44px height, `md` radius
- **Hint text:** `body-sm` in `on-surface-variant`
- **Progress indicator:** Hidden by default, shown during upload with spinner + "Scanning..." text

### Data Table

- **Wrapper:** `surface-bright` background, `lg` radius, Level 1 shadow, 1px border
- **Header row:** `surface-container-low` background, `label-sm` font (uppercase), 2px bottom border
- **Body cells:** `body-md` font, 12px 16px padding, 1px bottom border between rows
- **Hover:** Row background changes to `surface-container-low`
- **Rule column:** `mono` font
- **Resource column:** `mono` font
- **Remediation column:** `body-sm` in `on-surface-variant`

### Chart Cards

- **Container:** Same as stat-card styling (white, bordered, shadowed)
- **Title:** `headline-md` with `md` bottom margin
- **Doughnut chart:** 68% cutout, no border on segments, bottom legend with `label-lg` font
- **Line chart:** `primary` line, 0.3 tension, filled area at 8% opacity, colored point markers matching severity, y-axis 0-100

## Do's and Don'ts

### Do

- Use the severity scale consistently — Critical is always red, Low is always green
- Use `label-sm` uppercase for all table headers and metadata labels
- Use `mono` font for rule IDs, resource names, and any code-like content
- Keep the header green accent bar — it's a key WK brand element
- Use Level 1 shadow only for cards — flat everything else
- Let stat card values breathe — `display-lg` at 56px is intentionally large

### Don't

- Don't use `brand-red` (#e31937) for anything except Critical severity
- Don't add dark mode — WK corporate identity is light-themed
- Don't use colored shadows or gradients beyond the header
- Don't mix font families — Fira Sans for UI, Fira Code for code, nothing else
- Don't add rounded corners larger than `xl` (16px) except on pills
- Don't truncate severity badge text — always show full word (Critical, not Crit)
- Don't use icons without text labels — enterprise users expect explicit labels
