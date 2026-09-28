## 实现方案

### 1. 在 Rust 侧增加固定的更新检查命令
- 新增 `src-tauri/src/update.rs`，不引入新的网络依赖，复用项目现有的 `ureq`、TLS 与 `http_guard::PublicResolver`。
- 只允许访问固定地址：`https://api.github.com/repos/hahaha-taotao/sealbox/releases/latest`，不接受前端传入任意 URL，也不使用凭据。
- 请求使用 HTTPS、固定 GitHub Host、短超时、禁止自动重定向，并限制响应体大小；解析最新稳定 Release 的版本号、发布说明、发布时间、发布页地址和 assets。
- 严格校验返回的发布页/下载地址必须属于 `github.com/hahaha-taotao/sealbox/releases...`，避免 API 响应被利用成外部跳转。
- 从 assets 中优先选择 Windows x64 NSIS 安装包（优先匹配 `x64` 且以 `setup.exe` 结尾的资产，找不到时再退回其他 `setup.exe`）；不把不存在的文件名硬编码成下载链接。
- 返回 `current_version`、`latest_version`、`update_available`、`release_url`、`published_at`、截断后的 `notes` 和可选 `installer` 元数据。
- 在 `src-tauri/src/lib.rs` 注册 `check_for_updates` Tauri command。
- 为版本比较、资产选择、URL 校验、JSON 解析补充 Rust 单测，网络请求本身不放进测试。

### 2. 扩展前端 API 桥接和状态
- 在 `src/lib/tauri.ts` 增加更新结果和安装包类型，以及 `api.checkForUpdates()`。
- 在 `App.vue` 使用现有的 `@tauri-apps/plugin-opener` 的 `openUrl`：
  - “检查更新”按钮调用固定 Rust 命令，展示检查中、已是最新、发现新版本、检查失败等状态。
  - 若发现新版本且有安装包，点击“下载最新程序包”时交给系统默认浏览器下载 Release asset；应用不静默下载、不自动运行安装器。
  - 若最新 Release 没有安装包，显示“最新版本暂无安装包”，提供“打开发布页”按钮，避免错误地拼接 `Sealbox_<version>_x64-setup.exe`。
  - 显示当前版本、最新版本、发布时间和发布说明；对长说明做换行和长度限制。
- 当前版本显示使用现有 `package.json` 版本作为前端展示来源，更新检查结果同时以 Rust 编译版本为准；不新增路由或独立页面。

### 3. 在现有设置页内加入“关于”栏目
- 按用户所说的“设置里面”实现为设置页底部的新卡片，不新增侧栏入口、不新增 `Page` 状态。
- 接在现有“修改主密码”卡片之后，复用 `.mcp-card`、`.mcp-actions`、`.crumb` 等现有样式，补充少量关于/更新状态样式并适配窄窗口。
- 保留现有设置、Hello 和主密码流程不变；只有用户点击“检查更新”或下载按钮时才产生外网访问/外部打开行为。

### 4. 文档与验证
- 在 README 的安装/版本说明附近补充：更新检查来源为 GitHub Releases，下载由系统浏览器托管；Release 没有安装包时会回退到发布页。
- 实现后依次运行：
  - `npm run build`
  - `cargo fmt --manifest-path src-tauri/Cargo.toml --check`
  - `cargo test --manifest-path src-tauri/Cargo.toml`
  - `node --test extension/fill-logic.test.js`
- 再运行 `npm run tauri build` 做桌面打包回归，确认 NSIS 产物仍生成；手工冒烟检查设置页在 1280×800 和 960×640 下布局正常，并覆盖“已是最新 / 有更新 / 无安装包”的显示逻辑（网络结果可用固定测试数据/代码路径验证，不把当前无 asset 的 Release 误当成可下载）。

### 边界说明
- 当前 GitHub 最新 `v0.1.1` Release 已确认没有 assets，所以完成代码后，真实运行会正确显示“暂无安装包”而不是伪造下载地址；待 Release 上传 NSIS 安装包后，同一功能会自动出现直链下载按钮。
- 本次不自动上传 Release 资产、不创建 CI 发布流程，也不静默执行安装包；这些属于发布基础设施和高风险外部动作，超出“设置里的关于/更新”功能本身。