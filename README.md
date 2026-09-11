# Sealbox 印盒

Windows 本地凭据金库。主密码（可选 Windows Hello）解锁；网站账号、API Token、SSH 私钥加密存放；复制后定时清空剪贴板；支持 `.svbak` 加密备份。可选本机 MCP，让 Cursor / Claude Code 使用凭据但看不到明文。

设计见 `docs/superpowers/specs/2026-09-11-local-credential-vault-design.md`。

## 开发

需要 Rust、Node.js。

```bash
npm install
npm run tauri dev
```

首次启动设主密码（至少 10 位）。关闭窗口进入托盘。全局热键默认 `Ctrl+Shift+Space`。

数据文件：`%APPDATA%\com.sealbox.app\vault.db`

## MCP

1. 解锁金库。
2. 左侧 **MCP** → **启动**（仅 `127.0.0.1`，默认端口 17891）。
3. 复制页面上的配置到 Cursor / Claude Code。

工具：

- `list_credentials`：只返回名称、类型、账号，不含秘密。
- `http_request`：本机代填 Authorization，响应脱敏。
- `copy_secret`：复制到本机剪贴板，不把明文返回给模型。

金库锁定时工具会失败并提示先解锁。Token 可在页面轮换。

## 测试

```bash
cargo test --manifest-path src-tauri/Cargo.toml
```
