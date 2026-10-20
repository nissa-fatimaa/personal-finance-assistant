import { resolve } from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const appDirectory = resolve(import.meta.dirname);

export default defineConfig({
  root: appDirectory,
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5000,
    strictPort: true,
    allowedHosts: true,
  },
  build: {
    outDir: resolve(appDirectory, "../app/static"),
    emptyOutDir: true,
    sourcemap: false,
  },
  test: {
    environment: "happy-dom",
    setupFiles: ["./src/test-setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    restoreMocks: true,
  },
});
