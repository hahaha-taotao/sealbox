# 浏览器 TOTP 填充与 CSV 导入 — 设计

日期：2026-09-24  
状态：已确认（规划）  
产品名：Sealbox（印盒）

## 1. 目标

把已经存在金库里的网站 TOTP 接到 Chrome / Edge 填表链路上，并提供本机 CSV 导入，让日常登录和冷启动不再依赖手工复制。

一句话：人在登录页点一下就能填账号、密码和当前验证码；从浏览器 / Bitwarden / 1Password 导出的 CSV 可以预览后写入金库。

## 2. 已确认决策

| # | 决策点 | 结论 |
|---|---|---|
| 1 | TOTP 明文形态 | 扩展只拿到当前 6 位码，永不拿到 `totp_secret` |
| 2 | 同页 / 分步 | 同页有验证码框则一次填入；分步登录把 6 位码暂存 `chrome.storage.session`，过期或锁定即清 |
| 3 | 导入来源 | 用户自选 CSV 文件。支持 Chrome/Edge、Bitwarden、1Password 导出头，以及 Sealbox 通用头 |
| 4 | 不读浏览器登录库 | 不解析 Chrome `Login Data` SQLite，不碰 DPAPI |
| 5 | 预览脱敏 | 前端只看到标题、网址、账号、是否有密码/TOTP；密码和密钥不进 Vue |
| 6 | 合并策略 | 默认按「同源 + 账号」跳过已有条目；显式勾选后才覆盖密码/TOTP |
| 7 | 明确不做 | Passkey、Firefox、HIBP、扫描导入、自动从浏览器读登录库 |

## 3. TOTP 填充

### 3.1 金库

`SecretPayload::Website.totp_secret` 继续只存规范化后的 Base32 密钥。保存与导入时接受：

- 裸 Base32（可含空格、横线）
- `otpauth://totp/...` URI（读取 `secret`；`digits`/`period`/`algorithm` 非 SHA1/6/30 时拒绝并提示）

列表仍只暴露 `has_totp`。

### 3.2 填表协议

`GET` 语义不变，仍是本机 POST JSON。

`/fill/match` 的每条匹配增加 `has_totp: bool`。

`/fill/secret` 的 `entry` 增加：

```json
{
  "id": "...",
  "title": "...",
  "username": "...",
  "password": "...",
  "totp": "123456",
  "totp_period_remaining": 18
}
```

无 TOTP 时 `totp` 为 `null`。码由 Rust `totp_now` 生成。审计仍记 `browser_fill`，不记码。

### 3.3 扩展行为

1. 同页同时有密码框和验证码框：一次写入用户名、密码、6 位码。
2. 只有密码框：只填账号密码；若 `totp` 非空，把 `{ code, remaining, url, username, at }` 写入 session，TTL = `min(remaining, 30)` 秒。
3. 后续导航到同站且检测到验证码框、session 未过期：自动填入 6 位码，然后删除 session 项。
4. 金库锁定、配对失效、站点排除列表命中：不填、不清金库，只清 session 中的 pending TOTP。
5. 选择器可显示「有验证码」标记，但不展示 6 位码。

验证码框启发式（须可单测）：`autocomplete=one-time-code`；`maxlength` 为 6 或 8 的数字框；name/id/placeholder/aria-label 匹配 `otp|totp|2fa|mfa|one[-_ ]?time|verification|验证码|动态码|校验码`。密码框永不视为验证码框。

## 4. CSV 导入

### 4.1 入口

保险库侧栏「备份 / 还原」旁增加「从 CSV 导入」。必须已解锁。选文件在 Rust 侧读盘。

### 4.2 格式探测（按表头，忽略 BOM 与大小写）

| 格式 | 必要列 |
|---|---|
| Chrome / Edge | `name,url,username,password` |
| Bitwarden | `login_uri,login_username,login_password`（`login_totp`、`name`、`notes` 可选） |
| 1Password | `Title,Url,Username,Password`（`OTPAuth`、`Notes`、`Tags` 可选） |
| Sealbox | `title,url,username,password`（`totp,notes,tags` 可选） |

无法识别则失败，文案：「无法识别的 CSV 表头」。非 UTF-8 失败：「请将文件另存为 UTF-8」。

### 4.3 限制

- 文件 ≤ 5 MiB
- 行数 ≤ 5000（不含表头）
- 字段长度：title 200、url 2000、username 300、password 4096、totp 512、notes 8000
- 只导入网站登录行（Bitwarden `type` 若存在且不是 login 则跳过）
- 无密码且无 TOTP 的行跳过

### 4.4 命令

- `import_csv_preview(path) -> CsvImportPreview`
- `import_csv_commit(path, overwrite: bool) -> CsvImportResult`

预览字段：`format`、`total`、`importable`、`skipped_existing`、`skipped_invalid`、`sample`（最多 20 条元数据）。提交时重新读文件，不信任前端缓存的行内容。

审计：`import_csv`，detail 只含 format、inserted、skipped、overwrite。

## 5. 成功标准

1. 金库网站条目有 TOTP 时，登录页一次点击能填账号密码；同页或紧接着的验证码页能填入当前 6 位码。
2. 扩展存储、日志、overlay 文案都不出现 TOTP 密钥。
3. Chrome 导出 CSV 预览不展示密码，确认后条目可填充。
4. 已有同站同账号默认跳过；勾选覆盖后密码/TOTP 更新。
5. 现有填表测试与 `cargo test`、`node --test extension/fill-logic.test.js` 全绿。
