import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
// @ts-expect-error type error without @types/node package
import process from "node:process";
const host = process.env.TAURI_DEV_HOST;
const mobile = process.env.SEALBOX_MOBILE === "1";

// https://vite.dev/config/
export default defineConfig(() => ({
  plugins: [vue()],
  root: mobile ? "apps/mobile" : undefined,
  build: mobile
    ? { outDir: "dist", emptyOutDir: true }
    : {
        rollupOptions: {
          input: {
            main: "index.html",
            quick: "quick.html",
            confirm: "confirm.html",
          },
        },
      },

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: mobile ? 1421 : 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
}));
