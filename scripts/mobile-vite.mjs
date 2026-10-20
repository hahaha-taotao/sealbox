import { spawn } from "node:child_process";

const mode = process.argv[2] === "build" ? "build" : "";
const child = spawn(process.execPath, ["./node_modules/vite/bin/vite.js", mode].filter(Boolean), {
  stdio: "inherit",
  env: { ...process.env, SEALBOX_MOBILE: "1" },
  shell: false,
});
child.on("exit", (code) => process.exit(code ?? 1));
