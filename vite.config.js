import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

const mobile = process.env.SEALBOX_MOBILE === "1";

export default defineConfig({
  plugins: [vue()],
  root: mobile ? "apps/mobile" : undefined,
  clearScreen: false,
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
  server: {
    port: mobile ? 1421 : 1420,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**", "**/src-tauri-mobile/**"] },
  },
});
