/**
 * Bastión Xólot — "Obsidian Guardian" Design System
 * Apple dark-mode clarity meets Aztec ceremonial weight.
 *
 * bg:   OLED pure black (obsidian volcanic glass)
 * card: #1C1C1E — Apple's exact elevated surface in dark mode
 * jade: #30D158 — Apple system green — guardian / alive
 * gold: #C9A24C — Aztec sacred solar metal — brand / ceremony
 * red:  #FF453A — Apple system red — danger / blood sacrifice
 */

export const T = {
  // ── Backgrounds ──────────────────────────────────────────
  bgBase:         '#000000',   // OLED obsidian black
  bgCard:         '#1C1C1E',   // Apple dark card (exact match)
  bgCardElevated: '#2C2C2E',   // raised surface
  bgInput:        '#0E0E12',

  // ── Text ─────────────────────────────────────────────────
  textPrimary:   '#F2F2F7',   // Apple primary label
  textSecondary: '#8E8E93',   // Apple secondary label
  textMuted:     '#48484A',   // Apple tertiary label
  textGold:      '#C9A24C',

  // ── Accent colours ───────────────────────────────────────
  jade:      '#30D158',   // Apple system green
  gold:      '#C9A24C',   // Aztec sacred gold
  turquoise: '#32ADE6',   // Apple system blue
  danger:    '#FF453A',   // Apple system red
  warning:   '#FF9F0A',   // Apple system orange

  // Readable text variants on dark backgrounds
  jadeText:       '#34C759',
  turquoiseText:  '#64D2FF',
  dangerText:     '#FF6961',
  warningText:    '#FFB340',
  goldText:       '#DEB96A',

  // ── Borders (rgba — used minimally) ──────────────────────
  borderSubtle:    'rgba(255,255,255,0.10)',
  borderGold:      'rgba(201,162,76,0.50)',
  borderJade:      'rgba(48,209,88,0.40)',
  borderDanger:    'rgba(255,69,58,0.50)',
  borderWarning:   'rgba(255,159,10,0.45)',
  borderTurquoise: 'rgba(50,173,230,0.40)',

  // ── Status pill fills ────────────────────────────────────
  pillOkBg:      'rgba(48,209,88,0.15)',
  pillWarnBg:    'rgba(255,159,10,0.15)',
  pillBadBg:     'rgba(255,69,58,0.15)',
  pillNeutralBg: 'rgba(50,173,230,0.15)',

  // ── Navigation ───────────────────────────────────────────
  tabBar:      '#000000',
  tabActive:   '#30D158',
  tabInactive: '#48484A',

  headerBg:   '#000000',
  headerText: '#F2F2F7',
} as const;
