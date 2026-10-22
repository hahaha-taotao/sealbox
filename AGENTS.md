# Sealbox 项目约定

## 构建与发布

- **每次构建都必须同时产出桌面版和 Android 版，不允许只构建其中一端。**
  发布入口只有 `.github/workflows/release.yml`：推 `vX.Y.Z` 或 `mobile-vX.Y.Z` tag 会同时跑
  `release`（Windows 安装包）和 `android`（arm64 APK）两个 job，两个产物挂在同一个 Release 上。
  不要再新增只构建单一平台的 workflow——原来的 `android.yml` 就是因此并进 `release.yml` 的。
- 版本号是两条独立的线：
  - 桌面 `vX.Y.Z`：`package.json`、`package-lock.json`、`src-tauri/Cargo.toml`、
    `src-tauri/tauri.conf.json`、`extension/manifest.json`。
  - 移动 `mobile-vX.Y.Z`：`src-tauri-mobile/tauri.conf.json`、`src-tauri-mobile/Cargo.toml`、
    `Cargo.lock` 里的 `sealbox-mobile`。
  `scripts/check-version.mjs` 按 tag 前缀选择对应的一组字段校验，改版本号时这几处要一起改。
- 同一个 ref 被重复触发时由 workflow 的 `concurrency` 合并，只保留最新一套构建。
- 桌面自动更新读取 `releases/latest/download/latest.json`。因此每次发布会校验
  `latest.json` 确实上传成功；`mobile-v*` 发布后先把该 Release 的 latest 标记取消，
  再把最新的桌面 `v*` Release 显式标记为 latest，保证“latest”始终指向桌面发布，
  避免移动发布抢占“latest”后桌面更新报 `Could not fetch a valid release JSON from the remote`。

## 本地开发

- 桌面端：`npm run dev`。
- 移动端前端：`npm run mobile:dev`（Vite，端口 1420）。
- 移动端前端在**普通浏览器**里跑不通 `invoke`——那里没有 Tauri 运行时，
  `Cannot read properties of undefined (reading 'invoke')` 是预期结果，不是代码缺陷。
  要在电脑上验证移动端逻辑，只能跑 `tauri android dev`，或构建 APK 装到真机。
