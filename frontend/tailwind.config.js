/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Surfaces (light enterprise)
        canvas: "#FAFAFB", // app background
        surface: "#FFFFFF", // panels
        elevated: "#FFFFFF",
        line: "#E9E9EE", // hairline borders
        "line-strong": "#DEDEE5",
        // Ink (no pure black)
        ink: "#101013", // headings / strong text
        body: "#3F3F46", // body text
        muted: "#71717A", // secondary
        faint: "#A1A1AA", // tertiary / placeholders
        // Brand — NEX purple (disciplined single accent, no glow)
        brand: {
          DEFAULT: "#6D28D9",
          50: "#F6F4FE",
          100: "#EDE9FE",
          200: "#DDD6FE",
          600: "#7C3AED",
          700: "#6D28D9",
          800: "#5B21B6",
        },
        // Functional status (data semantics only — desaturated)
        blind: "#E11D48", // uncovered / blind spot / tier "none"
        "blind-soft": "#FFF1F3",
        secure: "#059669", // covered / closed / tier "good"
        "secure-soft": "#ECFDF5",
        warn: "#B45309", // partial visibility / tier "partial"
        "warn-soft": "#FFFBEB",
        // Terminal surface for SPL/Sigma (uses black in the palette)
        term: "#0B0B0F",
      },
      fontFamily: {
        sans: ["Geist", "system-ui", "sans-serif"],
        mono: ["Geist Mono", "ui-monospace", "monospace"],
      },
      borderRadius: {
        md: "8px",
        lg: "10px",
        xl: "14px",
      },
      boxShadow: {
        // diffusion shadows tinted to background — never neon glows
        card: "0 1px 2px rgba(16,16,19,0.04), 0 8px 24px -16px rgba(16,16,19,0.10)",
        pop: "0 12px 32px -12px rgba(16,16,19,0.18)",
      },
      keyframes: {
        breathe: { "0%,100%": { opacity: "1" }, "50%": { opacity: "0.4" } },
        shimmer: { "100%": { transform: "translateX(100%)" } },
      },
      animation: {
        breathe: "breathe 1.8s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
