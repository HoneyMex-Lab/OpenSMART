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
