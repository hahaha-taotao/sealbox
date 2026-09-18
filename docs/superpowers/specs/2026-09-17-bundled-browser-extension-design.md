# 客户端内嵌浏览器扩展安装向导 — 设计

日期：2026-09-17  
状态：已确认  
产品名：Sealbox（印盒）

## 0. 已确认决策

| # | 决策点 | 结论 |
|---|---|---|
| 1 | 分发形态 | **方案 A：扩展随安装包走，导出到本机固定目录，用户在 Chrome / Edge 里「加载已解压的扩展」** |
| 2 | 商店上架 | **本期不做** Chrome 应用店 / Edge 加载项；不预留商店按钮 |
| 3 | 安装方式 | **不写注册表、不发 `.crx`、不静默加载**。客户端只复制文件、打开目录、打开扩展管理页 |
| 4 | 导出路径 | 固定 `%LOCALAPPDATA%\com.sealbox.app\extension\`（Tauri `app_local_data_dir()/extension`） |
| 5 | 页面结构 | 「插件」页拆成两段：上面安装向导，下面沿用现有配对 / 填表 Token |

## 1. 目标

装完 Sealbox 的人不必再去仓库找 `extension/`。在侧栏「插件」页就能把扩展落到本机，并按步骤在 Chrome / Edge 里加载。配对、填表 Token、loopback 填表接口都不改。

当前文案已经失效：它要求用户选择「仓库里的 `extension` 目录」，安装包用户没有这份源码。

## 2. 约束

1. Chrome / Edge **不允许**桌面程序替用户安装 unpacked 扩展。开发者模式和「加载已解压的扩展」必须人手点。
2. unpacked 扩展的身份跟**目录路径**绑定。导出路径必须稳定，不能每次换临时目录。
3. `chrome://extensions` / `edge://extensions` 不能当普通 URL 用 ShellExecute 打开；已运行的 Chrome / Edge 也会丢掉命令行里的内部地址。必须启动对应浏览器可执行文件，再用地址栏（UI Automation）导航到扩展页。
4. 扩展只支持 Chrome / Edge（Manifest V3 + `chrome.*` API）。不为此期做 Firefox / Safari。
5. 金库锁定不影响「把文件复制到本机」；配对、显示 Token 仍要求已解锁。

## 3. 架构

```
仓库 extension/          tauri.conf 按白名单打进资源
        │
        ▼
安装包 resource_dir/extension/     tauri dev 则回退读仓库 extension/
        │  用户点「安装到本机」
        ▼
%LOCALAPPDATA%\com.sealbox.app\extension\
        │  打开目录 + 打开 chrome://extensions 或 edge://extensions
        ▼
用户：开发者模式 → 加载已解压的扩展 → 选这个文件夹 → 回 Sealbox 配对
```

Rust 新增小组件（建议 `src-tauri/src/extension_install.rs`），只负责：定位内置包、复制到固定目录、比较是否过期、探测 Chrome / Edge、打开目录和扩展页。不碰金库、填表 Token、MCP。

前端只在「插件」页调这几个命令。不把扩展文件读进 WebView。

## 4. 打包与文件白名单

`tauri.conf.json` 的 `bundle.resources` **按文件列出**运行所需文件，映射到资源目录下的 `extension/`。不要用 `../extension/**/*`，以免把测试打进安装包。

白名单（与当前 `extension/` 运行时文件一致）：

```
manifest.json
background.js
content.js
fill-logic.cjs
overlay-inject.js
overlay.html
overlay.js
page-fill.js
popup.css
popup.html
popup.js
```

明确不打包：`fill-logic.test.js`、以后出现的 `*.test.js` / `*.md`。

复制到本机时再次按同一白名单写入。目录里多出来、且不在白名单中的文件删掉，避免旧版本残留脚本仍被 Chrome 加载。先写入目标目录（覆盖同名文件），再删除白名单外的条目；不要先删整个目录，以免扩展正被浏览器加载时文件夹消失。

内置包定位顺序：

1. `app.path().resource_dir()/extension/`，且其中有 `manifest.json`
2. 开发回退：`CARGO_MANIFEST_DIR/../extension/`（`tauri dev` 未打资源时）
3. 两处都没有则安装命令失败，文案：「找不到内置扩展，请重新安装 Sealbox。」

## 5. 本机目录与更新检测

| 项 | 值 |
|---|---|
| 目录 | `app.path().app_local_data_dir()/extension`，即 `%LOCALAPPDATA%\com.sealbox.app\extension\` |
| 金库 | 仍在 `app_data_dir()/vault.db`（`%APPDATA%`），互不混放 |

「已安装」：目标目录存在 `manifest.json`。

「需要更新」：已安装，但与内置包不一致。比较方式：

1. 先比两边 `manifest.json` 的 `version`
2. 再比对白名单文件的 SHA-256（按相对路径排序后拼接）。同一版本改了脚本（开发期常见）也会提示更新

打开「插件」页时只做检查，**不自动覆盖**。用户点安装 / 更新才写盘。

版本号继续跟应用走：扩展 `manifest.json` 的 `version` 与 `tauri.conf.json` / 应用版本对齐；发版时改一处即可，实现阶段用现有 `0.1.0`，不另开扩展版本线。

## 6. 浏览器探测与打开

只认 **Chrome 稳定版** 和 **Edge 稳定版**。不为此期覆盖 Beta / Dev / Canary / Brave / 360。

探测顺序（Windows）：

1. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe`（及 `msedge.exe`）；再查 `HKCU` 同一路径
2. 常见安装位置：  
   Chrome：`%ProgramFiles%\Google\Chrome\Application\chrome.exe`、`%ProgramFiles(x86)%\...`、`%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe`  
   Edge：`%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe`、`%ProgramFiles%\Microsoft\Edge\Application\msedge.exe`

可执行文件路径必须是探测结果。禁止把用户输入、扩展目录里的文件、或任意 URL 当成要启动的程序。

打开方式：

| 动作 | 做法 |
|---|---|
| 打开扩展目录 | `explorer.exe` + 目标目录。目录不存在则先提示去安装 |
| 打开 Chrome 扩展页 | 若已有 Chrome 窗口则不再启动进程，直接把地址栏导航到 `chrome://extensions`；没有窗口才启动 `chrome.exe` |
| 打开 Edge 扩展页 | 若已有 Edge 窗口则不再启动进程，直接把地址栏导航到 `edge://extensions`；没有窗口才启动 `msedge.exe` |

找不到对应浏览器：按钮禁用，旁注「未检测到 Google Chrome」或「未检测到 Microsoft Edge」。目录路径仍可复制，用户可手动加载。

## 7. 命令

四个 invoke，均不要求金库已解锁。

### 7.1 `extension_install_status`

返回：

```ts
{
  dest_path: string
  bundled_version: string
  installed: boolean
  installed_version: string | null
  outdated: boolean
  chrome: { available: boolean }
  edge: { available: boolean }
}
```

`outdated` 仅在 `installed == true` 且与内置包不一致时为 true。内置包缺失时命令失败。

### 7.2 `extension_install`

按白名单把内置包覆盖到 `dest_path`，返回更新后的 status。失败时返回可读中文原因（源不存在、目标不可写等），不回完整内部路径堆栈。

成功后**自动打开**该目录（资源管理器）。不自动打开浏览器扩展页，以免同时弹出两个窗口、用户不知道先看哪。

### 7.3 `extension_open_folder`

打开已导出目录。尚未安装则失败：「请先安装到本机。」

### 7.4 `extension_open_browser`

参数：`browser: "chrome" | "edge"`。启动对应浏览器，并把地址栏导航到扩展页；成功时返回该地址。未检测到则失败，文案与按钮旁注一致。

前端封装在现有 `src/lib/tauri.ts`。

## 8. 插件页

仍是一张主卡片，顺序改为：

1. **安装扩展**  
   - 本机目录（等宽、可复制）  
   - 状态一行，三选一：尚未安装；已安装且与内置包一致（显示版本）；已安装但 outdated。outdated 时若版本不同，写「已安装 · vA，内置 vB，请更新后再到浏览器点刷新」；版本相同而文件哈希不同，写「已安装 · vX，内置文件已更新，请重新安装后再到浏览器点刷新」  
   - 主按钮：未安装或需更新时为「安装到本机并打开目录」（忙碌态「正在安装…」）；已是最新则为「重新安装并打开目录」  
   - 次按钮：「打开目录」「打开 Chrome 扩展页」「打开 Edge 扩展页」（后两个按探测结果启用）  
   - 固定三步，不因状态隐藏：  
     1. 打开开发者模式  
     2. 加载已解压的扩展  
     3. 选择上面这个文件夹  
   - 副文案：升级 Sealbox 后若提示更新，先点安装覆盖文件，再回扩展页点刷新。路径不要改。

2. **配对**  
   现有「配对」「轮换填表 Token」、配对码、Token 显示/复制、fill URL 原样保留。  
   删掉「选择仓库里的 `extension` 目录」。改为：扩展加载成功后，点配对，60 秒内把一次性配对码填进扩展。

页头 crumb 改为：Chrome / Edge 扩展随客户端分发。先安装到本机再加载，然后配对。配对码一次性有效；填表 Token 与 MCP Token 分开。

进入插件页时拉一次 `extension_install_status`。status 失败、安装失败、打开失败都显示在安装段，不占用配对段的 `pairingError`。status 失败时安装按钮仍可点（便于重试），打开目录 / 打开浏览器按钮禁用。

## 9. 安全

| 项 | 规则 |
|---|---|
| 写入范围 | 只写 `app_local_data_dir()/extension` |
| 读取范围 | 只读内置资源目录或开发回退的仓库 `extension/` |
| 启动进程 | 只启动探测到的 `chrome.exe` / `msedge.exe` / `explorer.exe` |
| 参数 | 启动浏览器时不传 `chrome://` / `edge://`；扩展页地址只通过地址栏写入，不作为命令行参数 |
| 不做什么 | 不写 `ExtensionInstallForcelist` 等策略；不下载远程扩展；不执行扩展目录里的脚本；不把扩展文件注入页面 |

复制过程不读、不记录、不上传扩展内容。审计：此期不写 `vault.audit`（无秘密、不依赖解锁）。若以后要记，只记「安装扩展」动作，不记文件哈希以外的内容。

## 10. 失败与文案

| 情况 | 用户可见 |
|---|---|
| 找不到内置包 | 找不到内置扩展，请重新安装 Sealbox。 |
| 目标目录无法创建或写入 | 无法写入扩展目录，请检查磁盘权限。 |
| 尚未安装就打开目录 | 请先安装到本机。 |
| 未检测到 Chrome / Edge | 未检测到 Google Chrome / 未检测到 Microsoft Edge。 |
| 启动浏览器失败 | 无法打开扩展页，请手动访问 chrome://extensions（Chrome）或 edge://extensions（Edge）。 |

目录路径始终展示，安装失败后仍可复制，方便手工加载。

## 11. 测试

Rust 单测（不启 UI、不启真浏览器）：

- 白名单复制：只写出白名单文件；目标里多余的 `evil.js` 被删；`fill-logic.test.js` 不会出现在目标目录
- 过期检测：版本不同 → outdated；版本相同但某白名单文件内容不同 → outdated；完全一致 → 否
- 目标路径：以假的 `app_local_data_dir` 为根，结果必须是其下的 `extension`，不能写出根目录以外
- 内置包缺失 → 安装失败

浏览器探测可用带假注册表/路径的内部函数测「有 / 无」；真正 `Command::spawn` 不在 CI 里打真实 Chrome。

现有 `node --test extension/fill-logic.test.js` 保持。扩展脚本行为此期不改。

## 12. 文档

实现时改 README「插件 Plugin」节：安装步骤改为从 Sealbox「插件」页安装到本机，再在 `chrome://extensions` / `edge://extensions` 加载该目录。删掉「选择仓库里的 `extension` 目录」作为常规路径；开发者仍可直接 load 仓库 `extension/` 做调试。

## 13. 明确不做

- Chrome 应用店 / Edge 加载项、`.crx` 拖放安装
- Firefox / Safari / Brave 适配或按钮
- 注册表强制安装、企业策略
- 自动打开开发者模式、模拟点击「加载已解压的扩展」
- 安装成功后自动弹配对
- 改填表协议、配对码、Token 存储
- 给扩展加图标、改 Manifest 权限（除非打包时发现缺文件无法加载）

## 14. 成功标准

1. `tauri build` 的安装包能在没有仓库源码的机器上，从「插件」页把扩展导出到 `%LOCALAPPDATA%\com.sealbox.app\extension\`。
2. `tauri dev` 在未配置资源时，仍能从仓库 `extension/` 导出同一组运行时文件。
3. 目标目录不含测试文件。
4. 已加载该目录的 Chrome / Edge，在 Sealbox 升级并点更新后，刷新扩展即可用新脚本；路径不变，不必移除重装。
5. 未装 Chrome 时，Chrome 按钮不可用且有说明；Edge 同理。配对流程与锁定前行为与现在一致。
)
