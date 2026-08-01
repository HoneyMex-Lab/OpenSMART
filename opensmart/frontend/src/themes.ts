export type ThemeOption = { value: string; label: string };

// Selectable UI themes. Keep values in sync with styles.css
// (:root[data-theme="…"]) and the backend's ALLOWED_THEMES.
export const THEME_OPTIONS: ThemeOption[] = [
  { value: 'honeynet', label: 'Honeynet' },
  { value: 'dark', label: 'Dark' },
  { value: 'classic', label: 'Classic (light)' },
  { value: 'matrix', label: 'Matrix' },
  { value: 'energy', label: 'Energy' },
];

// Applied when neither the user nor the admin default resolves to a theme.
export const DEFAULT_THEME = 'honeynet';

export type ThemeSwatch = { background: string; surface: string; accent: string; accent2: string };

// A handful of representative colors per theme (page background, card
// surface tint, and two accent colors), read directly from each theme's
// :root[data-theme="…"] block in styles.css. Used to render a quick
// color-scheme preview next to theme pickers — update these if the
// underlying CSS variables' values change.
export const THEME_SWATCHES: Record<string, ThemeSwatch> = {
  dark: { background: '#05070b', surface: '#202734', accent: '#58d7ff', accent2: '#63e6be' },
  honeynet: { background: '#060605', surface: '#1e1d1c', accent: '#d0a843', accent2: '#77d2b6' },
  classic: { background: '#e8ecf3', surface: '#c5ccd9', accent: '#0985ac', accent2: '#22a079' },
  matrix: { background: '#030d04', surface: '#0f4517', accent: '#58ff73', accent2: '#63e678' },
  energy: { background: '#080808', surface: '#2c2b28', accent: '#ffcf3d', accent2: '#73d6b8' },
};
