# Sealbox 印盒

Windows 本地凭据金库。主密码（可选 Windows Hello）解锁；网站账号、API Token、SSH 私钥加密存放；复制后定时清空剪贴板；支持 `.svbak` 加密备份。

第一版不做云同步、浏览器填充、MCP。设计见 `docs/superpowers/specs/2026-09-11-local-credential-vault-design.md`。

## 开发

需要 Rust、Node.js。

```bash
npm install
npm run tauri dev
```

首次启动设主密码（至少 10 位）。关闭窗口会进入托盘；托盘可选打开 / 锁定 / 退出。窗口聚焦时 `Ctrl+Shift+Space` 打开速查。

数据文件：`%APPDATA%\com.sealbox.app\vault.db`

## 测试

```bash
cargo test --manifest-path src-tauri/Cargo.toml
```
