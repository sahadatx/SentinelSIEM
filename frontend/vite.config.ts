import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const BACKEND_URL = "http://127.0.0.1:8001";

export default defineConfig({
  plugins: [react()],

  server: {
    host: "127.0.0.1",
    port: 8000,
    strictPort: true,

    proxy: {
      "/api": {
        target: BACKEND_URL,
        changeOrigin: true,
      },

      "/ws": {
        target: BACKEND_URL,
        changeOrigin: true,
        ws: true,
      },
    },

    hmr: {
      host: "localhost",
      port: 8000,
    },
  },

  preview: {
    host: "127.0.0.1",
    port: 8000,
    strictPort: true,

    proxy: {
      "/api": {
        target: BACKEND_URL,
        changeOrigin: true,
      },

      "/ws": {
        target: BACKEND_URL,
        changeOrigin: true,
        ws: true,
      },
    },
  },
});