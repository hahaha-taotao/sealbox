import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const tagPattern = /^v(\d+\.\d+\.\d+)$/;

function readText(relativePath) {
  return readFileSync(join(repoRoot, relativePath), "utf8");
}

function readJson(relativePath) {
  return JSON.parse(readText(relativePath));
}

function requireVersion(value, source) {
  if (typeof value !== "string" || !/^\d+\.\d+\.\d+$/.test(value)) {
    throw new Error(`${source} 的版本号无效：${String(value)}`);
  }
  return value;
}

function readCargoPackageVersion() {
  const lines = readText("src-tauri/Cargo.toml").split(/\r?\n/);
  let inPackage = false;

  for (const line of lines) {
    const section = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (section) {
      inPackage = section[1] === "package";
      continue;
    }
    if (!inPackage) continue;

    const version = line.match(/^\s*version\s*=\s*["']([^"']+)["']\s*(?:#.*)?$/);
    if (version) return requireVersion(version[1], "src-tauri/Cargo.toml [package].version");
  }

  throw new Error("src-tauri/Cargo.toml 缺少 [package].version");
}

function collectVersions() {
  const packageJson = readJson("package.json");
  const tauriConfig = readJson("src-tauri/tauri.conf.json");
  const manifest = readJson("extension/manifest.json");
  const packageLock = readJson("package-lock.json");

  return [
    ["package.json", requireVersion(packageJson.version, "package.json version")],
    ["src-tauri/Cargo.toml", readCargoPackageVersion()],
    ["src-tauri/tauri.conf.json", requireVersion(tauriConfig.version, "src-tauri/tauri.conf.json version")],
    ["extension/manifest.json", requireVersion(manifest.version, "extension/manifest.json version")],
    ["package-lock.json", requireVersion(packageLock.version, "package-lock.json version")],
    [
      "package-lock.json packages[\"\"].version",
      requireVersion(packageLock.packages?.[""]?.version, "package-lock.json packages[\"\"].version"),
    ],
  ];
}

function main() {
  const [tag, ...extraArgs] = process.argv.slice(2);
  if (!tag || extraArgs.length > 0) {
    throw new Error("用法：node scripts/check-version.mjs v0.1.5");
  }

  const match = tag.match(tagPattern);
  if (!match) {
    throw new Error(`发布 tag 必须是 vMAJOR.MINOR.PATCH 格式，收到：${tag}`);
  }
  const expectedVersion = match[1];
  const versions = collectVersions();
  const mismatches = versions.filter(([, version]) => version !== expectedVersion);

  if (mismatches.length > 0) {
    const details = mismatches.map(([source, version]) => `${source}=${version}`).join(", ");
    throw new Error(`版本不一致，期望 ${expectedVersion}：${details}`);
  }

  console.log(`版本校验通过：${tag}；${versions.length} 个版本字段均为 ${expectedVersion}`);
}

try {
  main();
} catch (error) {
  console.error(`版本校验失败：${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
