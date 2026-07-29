import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The frontend talks to the FastAPI backend. In development, requests to
// /api are proxied to the backend so there are no CORS concerns.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on("error", (err) => console.error("[vite proxy]", err));
        },
      },
    },
  },
  build: { outDir: "dist", sourcemap: false },
});
