import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        vault: {
          bg: "#110024",
          surface: "#1a0633",
          elevated: "#240c45",
          border: "#361861",
          accent: "#ab7eff",
          "accent-hover": "#9661ff",
          soft: "#f2ebff",
          muted: "#a998c9",
        },
      },
    },
  },
  plugins: [],
};
export default config;
