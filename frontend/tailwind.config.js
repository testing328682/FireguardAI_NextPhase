/** @type {import('tailwindcss').Config} */
// Color tokens are CSS variables (RGB channel triplets) so the same class names
// (`bg-base-900`, `text-ink-100`, …) resolve to either the dark or light palette
// depending on `data-theme` on <html>. See src/index.css for the palettes.
const ch = (v) => `rgb(var(${v}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: {
          900: ch("--base-900"), // page background
          800: ch("--base-800"), // panel
          700: ch("--base-700"), // raised panel
          600: ch("--base-600"), // border-strong
          500: ch("--base-500"), // hairline
        },
        ink: {
          100: ch("--ink-100"), // primary text
          300: ch("--ink-300"), // secondary text
          500: ch("--ink-500"), // muted text
        },
        sev: {
          critical: "#ff4d4d",
          high: "#ff8a3d",
          medium: "#f5c451",
          low: "#4a9eff",
          info: "#7a879b",
        },
        signal: "#39d98a", // positive / secure
        accent: ch("--accent"), // brand action
      },
      fontFamily: {
        display: ['"Space Grotesk"', "system-ui", "sans-serif"],
        sans: ['"Inter"', "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', '"SF Mono"', "ui-monospace", "monospace"],
      },
      borderRadius: { panel: "6px", chip: "4px" },
      boxShadow: { panel: "var(--shadow-panel)" },
    },
  },
  plugins: [],
};
