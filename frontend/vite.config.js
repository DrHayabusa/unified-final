import autoprefixer from "autoprefixer";
import react from "@vitejs/plugin-react";
import tailwindcss from "tailwindcss";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  base: "/",
  css: {
    postcss: {
      plugins: [
        tailwindcss({
          content: ["./index.html", "./src/**/*.jsx"],
          theme: {
            extend: {
              fontFamily: {
                display: ["Avenir Next", "Segoe UI Variable", "ui-sans-serif", "system-ui"],
                mono: ["IBM Plex Mono", "SFMono-Regular", "Consolas", "ui-monospace", "monospace"],
              },
              colors: {
                mva: {
                  cyan: "#22d3ee",
                  green: "#10b981",
                  lime: "#84cc16",
                  amber: "#f59e0b",
                  red: "#ef4444",
                },
              },
              boxShadow: {
                cyber: "0 24px 90px rgba(0, 0, 0, 0.62)",
                glow: "0 0 34px rgba(220, 38, 38, 0.25)",
              },
            },
          },
        }),
        autoprefixer(),
      ],
    },
  },
  server: {
    host: "127.0.0.1",
    port: 8891,
    proxy: {
      "/api": process.env.MVA_DEV_API_TARGET || "http://127.0.0.1:8890",
      "/health": process.env.MVA_DEV_API_TARGET || "http://127.0.0.1:8890",
    },
  },
  build: {
    // ExcelJS is intentionally lazy-loaded only when a user exports a workbook.
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (id.includes("/react/") || id.includes("/react-dom/") || id.includes("/scheduler/")) return "vendor-react";
          if (id.includes("/recharts/")) return "vendor-recharts";
          if (id.includes("/d3-") || id.includes("/internmap/") || id.includes("/decimal.js-light/")) return "vendor-d3";
          if (id.includes("/lucide-react/")) return "vendor-icons";
          return undefined;
        },
      },
    },
  },
});
