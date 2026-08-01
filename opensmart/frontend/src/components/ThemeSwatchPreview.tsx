import { DEFAULT_THEME, THEME_SWATCHES } from '../themes';

export default function ThemeSwatchPreview({ theme }: { theme: string }) {
  const swatch = THEME_SWATCHES[theme] || THEME_SWATCHES[DEFAULT_THEME];
  return (
    <div className="theme-swatch-preview">
      <span className="theme-swatch" style={{ background: swatch.background }} title="Background" />
      <span className="theme-swatch" style={{ background: swatch.surface }} title="Surface" />
      <span className="theme-swatch" style={{ background: swatch.accent }} title="Accent" />
      <span className="theme-swatch" style={{ background: swatch.accent2 }} title="Accent 2" />
    </div>
  );
}
