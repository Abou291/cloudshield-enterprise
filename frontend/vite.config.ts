import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig(({ mode }) => ({
  // A relative asset base is required when the desktop console loads index.html from disk.
  base: mode === "desktop" ? "./" : "/",
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: "./src/test-setup.ts",
    globals: true,
  },
}));
