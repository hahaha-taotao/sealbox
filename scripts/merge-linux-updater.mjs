// 把 Linux x64 的 updater 条目并进已有 latest.json。
// Windows 的 tauri-action 先上传 latest.json；Linux job 不能整文件覆盖，否则会丢掉 windows-*。

export function assertLinuxUpdaterAsset(assetName) {
  if (
    assetName.includes("/") ||
    assetName.includes("\\") ||
    assetName.endsWith(".sig") ||
    !(assetName.endsWith(".AppImage") || assetName.endsWith(".AppImage.tar.gz"))
  ) {
    throw new Error(`不是 AppImage updater 包: ${assetName}`);
  }
}

export function mergeLinuxUpdater(manifest, platform) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error("latest.json 不是对象");
  }
  if (!manifest.platforms || typeof manifest.platforms !== "object" || Array.isArray(manifest.platforms)) {
    throw new Error("latest.json 缺少 platforms");
  }
  const windowsKey = Object.keys(manifest.platforms).find((key) => key.startsWith("windows-"));
  if (!windowsKey) {
    throw new Error("latest.json 里没有 Windows 平台，拒绝写入");
  }
  const signature = String(platform?.signature ?? "").trim();
  const url = String(platform?.url ?? "").trim();
  if (!signature || !url) {
    throw new Error("缺少 Linux 签名或下载地址");
  }
  if (!url.startsWith("https://github.com/") || !url.includes("/releases/download/")) {
    throw new Error("Linux 下载地址不是 GitHub Release 资产");
  }
  return {
    ...manifest,
    platforms: {
      ...manifest.platforms,
      "linux-x86_64": { signature, url },
    },
  };
}

function arg(name) {
  const index = process.argv.indexOf(name);
  if (index === -1 || !process.argv[index + 1]) {
    throw new Error(`缺少参数 ${name}`);
  }
  return process.argv[index + 1];
}

async function main() {
  const { readFileSync, writeFileSync } = await import("node:fs");
  const latestPath = arg("--latest");
  const signaturePath = arg("--signature");
  const assetName = arg("--asset-name");
  const tag = arg("--tag");
  const repo = arg("--repo");
  const outPath = arg("--out");
  if (!/^v\d+\.\d+\.\d+$/.test(tag)) {
    throw new Error(`tag 格式不对: ${tag}`);
  }
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
    throw new Error(`repo 格式不对: ${repo}`);
  }
  assertLinuxUpdaterAsset(assetName);
  const manifest = JSON.parse(readFileSync(latestPath, "utf8"));
  const merged = mergeLinuxUpdater(manifest, {
    signature: readFileSync(signaturePath, "utf8"),
    url: `https://github.com/${repo}/releases/download/${tag}/${assetName}`,
  });
  if (!merged.platforms["windows-x86_64"] && !Object.keys(merged.platforms).some((key) => key.startsWith("windows-"))) {
    throw new Error("合并后丢失了 Windows 平台");
  }
  writeFileSync(outPath, `${JSON.stringify(merged, null, 2)}\n`);
}

if (import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` || process.argv[1]?.endsWith("merge-linux-updater.mjs")) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
