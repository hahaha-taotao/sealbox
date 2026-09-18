# ZoomKey JIRA / CRM 作为 MCP 能力 — 设计

日期：2026-09-17
状态：**已确认，开发中**

## 0. 已确认决策

| # | 决策点 | 结论 |
|---|---|---|
| 1 | 架构形态 | **Rust 原生实现，并入 Sealbox 现有本机 MCP**（方案 A） |
| 2 | 用户名 / 密码 / AccessKey | **复用金库 `ApiToken` 条目**（service = `zoomkey-jira` / `zoomkey-crm`） |
| 3 | mTLS 客户端证书 | **私钥存进金库**（新增 `EntryKind::ClientCert`） |
| 4 | 工具范围 | **全部 20 个只读工具**（JIRA 10 + CRM 10），共用一个 ZoomKey MCP 总开关；配齐的端点自动出现 |

## 1. 目标

把 `E:\project\openhanako\plugins\` 下 `zoomkey-jira` 与 `zoomkey-crm` 两个 HanaAgent 插件的
能力，搬进 Sealbox，成为 Sealbox 本机 MCP 的一部分，供 Cursor / Claude Code 等外部 AI 客户端调用。

关键约束：**访问地址与凭证不再写在插件的 `config.json` 明文里，而是从 Sealbox 金库取。**

## 2. 勘察结论（实测）

| 项 | 结论 |
|---|---|
| 插件格式 | `manifest.json` + `lib/client.js` + `tools/<name>.js`，导出 `name / description / parameters / execute(input, ctx)` |
| 宿主依赖 | 只有 `ctx.config.getAll()` 与 `ctx.dataDir` 两样，业务逻辑未绑死 Hana |
| 已存在桥接 | `plugins/zoomkey-bridge/` 已把两者包成 Node MCP stdio 服务（可参考，不复用其进程模型） |
| 工具数量 | JIRA 11 个（1 个 `configure` 写凭证）、CRM 11 个（1 个 `configure`） |
| JIRA 鉴权 | HTTP Basic（username + password），`GET /rest/api/2/...` |
| CRM 鉴权 | Vtiger：`getchallenge` → `md5(token + accessKey)` → `login` → `sessionName`，会话约 4 分钟 |
| **TLS** | **两个域名都强制 mTLS（客户端证书）**。实测：不带客户端证书 → `ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED`；带公司 CA bundle + client PEM → HTTP 200 |
| **解析地址** | `jira.zoomkey.com.cn` → `172.16.1.40`，`crm.zoomkey.com.cn` → `172.16.1.147`，**均为 RFC1918 内网地址** |
| 证书现状 | `D:\software\openhanako\plugin-data\zoomkey-jira\certs\` 下已有 `zoomkey-ca-bundle.pem` / `client-cert.pem` / `client-key.pem` |

两条实测结论直接决定方案形态：

1. **必须支持客户端证书（mTLS）**，这不是可选项。
2. **必须放开内网地址**，而 Sealbox 现有的 `http_guard::assert_public_target` 明确拦截
   RFC1918 / 回环 / 云元数据地址。这是本方案唯一的、需要刻意开口子的安全边界。

## 3. 架构

### 3.1 选定方案：Rust 原生实现，并入现有本机 MCP

新增 `src-tauri/src/zoomkey/` 模块，工具直接挂进 `mcp.rs` 现有的 `127.0.0.1:17891` MCP 服务，
与 `github_mcp` 同一套模式（策略开关 → 凭证绑定 → 固定目标请求 → 审计 → 脱敏）。

```
外部 AI 客户端
   │  Bearer <mcp_token>
   ▼
Sealbox 本机 MCP (127.0.0.1:17891)  ── mcp.rs 路由 ──┬── github_mcp   (api.github.com, 公网)
                                                     └── zoomkey      (zoomkey 内网, mTLS)   ← 新增
                                                            │
                                                            ├── 凭证 ← 金库 ApiToken 条目
                                                            ├── 客户端证书 ← 金库 ClientCert 条目
                                                            └── 策略 ← 金库 secret setting
```

### 3.2 备选方案与取舍

| 方案 | 做法 | 取舍 |
|---|---|---|
| **A. Rust 原生（选定）** | 在 Sealbox 内重写 JIRA/CRM 客户端 | 与现有 MCP 一致；凭证全程不出金库；有审计与策略。代价：需在 Rust 里做 mTLS，工作量最大 |
| B. 复用 Node 桥 | Sealbox 拉起 `zoomkey-bridge` 子进程做 stdio 代理 | 复用现成代码。代价：运行时要带 Node；凭证必须落到临时 `config.json` 明文，**违背金库的立身之本**。否决 |
| C. 独立远程 MCP 服务 | 另起一个可对外的 HTTP/SSE 服务 | 便于远程/团队共享。代价：内网 mTLS 凭证要落到服务端，且把内网系统暴露面扩大。本期不做 |

方案 B 的致命伤是"凭证必须落盘成明文"，与 Sealbox 的核心承诺冲突，因此不采用。

## 4. 凭证与配置模型

### 4.1 账号凭证：复用金库 `ApiToken` 条目

不新增类型，复用已有的 `ApiToken { service, account, token }`：

| 用途 | service | account | token |
|---|---|---|---|
| JIRA | `zoomkey-jira` | 登录用户名 | 登录密码 |
| CRM | `zoomkey-crm` | 登录用户名 | Vtiger AccessKey |

理由：`github_mcp` 已经用 `service` 做判别（`service == "github"`），同一套机制直接扩展；
零 DB schema 变更、零备份格式变更。

### 4.2 客户端证书：新增 `EntryKind::ClientCert`

私钥不进磁盘明文，改为**加密存进金库**。

```rust
// vault.rs
pub enum EntryKind { ..., ClientCert }          // "client_cert"

SecretPayload::ClientCert {
    cert_pem: String,        // 客户端证书 PEM 全文
    key_pem: String,         // 客户端私钥 PEM 全文（敏感）
    passphrase: Option<String>,
}
```

- 一个 ClientCert 条目可同时给 JIRA 和 CRM 用（实测同一套 `client-cert.pem` / `client-key.pem` 对两个域名都通）。
- UI 通过文件选择器提交证书和私钥路径，Rust 侧限长（证书、私钥各 512 KiB，总计 1 MiB）、解析 PEM 并校验证书/私钥匹配后写入 `secret_blob`；不保存原始路径，不把私钥返回到 WebView、剪贴板、MCP 或助手。
- 编辑已有条目时可以只改标题、标签、备注等元数据；替换密钥必须重新选择文件。公开证书 PEM 允许通过显式操作复制，私钥不提供复制或导出。
- **CA bundle 仍走文件路径**：它是公开的根证书链，不是机密，没必要进金库，也没必要让用户粘贴。
- 改动面（全部 serde 驱动，无数据库迁移 —— `kind` 是 TEXT 列）：
  `vault.rs`（枚举 + `as_str` / `parse` / `upsert_entry` / `counts_for` / `Counts`）、
  `commands.rs`（计数）、`src/lib/tauri.ts`（类型）、`src/App.vue`（类型列表、标签、筛选、编辑表单、明文查看）。

### 4.3 策略：金库 secret setting `zoomkey_mcp_policy`

```json
{
  "enabled": false,
  "allowed_hosts": ["jira.zoomkey.com.cn", "crm.zoomkey.com.cn"],
  "jira": {
    "base_url": "https://jira.zoomkey.com.cn",
    "credential_id": "",
    "client_cert_id": "",
    "ca_bundle_path": "",
    "default_max_results": 50
  },
  "crm": {
    "base_url": "https://crm.zoomkey.com.cn/webservice.php",
    "credential_id": "",
    "client_cert_id": "",
    "ca_bundle_path": ""
  }
}
```

默认关闭。启用 ZoomKey 工具需要同时满足：`enabled` +
`credential_id` 指向对应 service 的活动条目 + `client_cert_id` 指向有效证书条目 + CA bundle 路径有效。
JIRA 与 CRM 不再各挂启用勾选；配齐的端点自动出现在 `tools/list`。
旧策略里的 `jira_enabled` / `crm_enabled` / `allow_private_network` 任一为真，加载时迁成 `enabled=true`。

## 5. 工具清单

命名沿用 Sealbox 习惯（下划线），与插件原名一一对应，便于对照排障。

### 5.1 JIRA（`zoomkey_jira_*`，共 10 个，去掉 `configure`）

`nav`、`connection_status`、`list_projects`、`project_statuses`、`field_map`、
`search_issues`、`get_issue`、`my_open_issues`、`project_unfinished`、`preset_unfinished`

只读 REST：`GET /rest/api/2/{serverInfo,project,project/{key}/statuses,field,search,issue/{key}}`。

### 5.2 CRM（`zoomkey_crm_*`，共 10 个，去掉 `configure`）

`nav`、`connection_status`、`describe_module`、`field_map`、`find_account`、
`find_project`、`list_service_contracts`、`project_members`、`query`、`retrieve`

Vtiger 操作：`getchallenge / login / describe / listtypes / query / retrieve`。

> `zoomkey_crm_query` 只接受单条、受限的 SELECT 查询；结果经过字段与大小过滤后返回，不提供 `crm.expose_raw_query` 开关，也不允许写操作或多语句。

### 5.3 关于 `configure`

两个插件的 `configure` 会写凭证，**一律不移植**。配置改由 Sealbox 界面 + 金库承担。

## 6. 安全模型

| 项 | 设计 |
|---|---|
| 监听 | 不变，仍只 `127.0.0.1`，Bearer `mcp_token` |
| 金库锁定 | 锁定即所有 zoomkey 工具失败并提示先解锁（与 github 一致） |
| 默认状态 | 全部关闭。启用 ZoomKey MCP 等于同意访问白名单内网；配齐的端点自动出现 |
| 内网例外 | 只对 `allowed_hosts` 中的**精确主机名**放开；其余仍走 `assert_public_target`。github 路径完全不受影响 |
| DNS 重绑定 | 解析一次并**钉住** IP（自定义 `ureq::Resolver` 只返回已校验地址），校验与使用之间不重解析 |
| 模型可控面 | 不接受模型传入 URL / Host / Header / HTTP 方法。路径由代码按固定模板拼装，参数做白名单与转义 |
| 出站方法 | JIRA 仅 GET；CRM 仅 GET + POST（表单），仅指向配置的 `base_url` |
| 响应上限 | JIRA 4 MiB、CRM 8 MiB（对齐插件 manifest），超限即截断报错；文本字段各自截断 |
| 脱敏 | 返回体统一过 `redact_text`，屏蔽密码 / AccessKey / Vtiger `sessionName` |
| 审计 | 每次调用写 `vault.audit`：`operation / decision / reason / host / path / status / count / credential指纹`，不记明文 |
| 日志 | 不打印任何凭证与响应体 |
| TLS | 不复用"跳过校验"开关；`insecureSkipTlsVerify` **不移植** |

### 6.1 新增 TLS 能力

现有 `ureq 2.12.1`（rustls 0.23 + ring 后端）已支持 `AgentBuilder::tls_config(Arc<ClientConfig>)`。
需要新增两个直接依赖：

- `rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12", "logging"] }`
- `rustls-pemfile = "2"`
- `md-5 = "0.10"`（Vtiger 的 `md5(token + accessKey)`）

用 `ClientConfig::builder_with_provider(ring provider)` + 公司 CA 根证书 + `with_client_auth_cert()`
构造，按证书内容哈希缓存，避免每次请求重建。

## 7. 改动清单

| 文件 | 改动 |
|---|---|
| `src-tauri/Cargo.toml` | 新增 `rustls`、`rustls-pemfile`、`md-5` |
| `src-tauri/src/vault.rs` | 新增 `EntryKind::ClientCert` + `SecretPayload::ClientCert`；`Counts.client_cert`；`counts_for` 分支 |
| `src-tauri/src/zoomkey/mod.rs` | 新增：模块入口、策略读写、工具路由、审计 |
| `src-tauri/src/zoomkey/tls.rs` | 新增：ClientConfig 构造与缓存、PEM 解析 |
| `src-tauri/src/zoomkey/target.rs` | 新增：主机白名单、内网例外、IP 钉住 Resolver |
| `src-tauri/src/zoomkey/jira.rs` | 新增：JIRA 客户端 + 10 个工具 |
| `src-tauri/src/zoomkey/crm.rs` | 新增：Vtiger 客户端（含会话缓存）+ 10 个工具 |
| `src-tauri/src/mcp.rs` | `tools_list` 合并 zoomkey 工具；`call_tool` 增加 zoomkey 路由与审计 |
| `src-tauri/src/lib.rs` | 注册 `pub mod zoomkey;` 与新增命令 |
| `src-tauri/src/commands.rs` | 新增 `zoomkey_policy_get` / `zoomkey_policy_set` / `zoomkey_test_connection` / `zoomkey_candidates` |
| `src/lib/tauri.ts` | 新增对应前端 API 封装与类型 |
| `src/App.vue` | 新增 `client_cert` 条目类型；MCP 页新增「ZoomKey 集成」卡片 |
| `README.md` | MCP 一节补充 ZoomKey 工具与内网说明 |

**不动** `E:\project\openhanako\plugins\` 下任何文件（只作只读参考）。

## 8. 实施顺序

1. **金库扩展** — `EntryKind::ClientCert` 全链路（Rust + 前端），此时与 ZoomKey 无关，可独立验证
2. **策略与凭证骨架** — `zoomkey/mod.rs` 策略读写、候选凭证列举、命令与前端卡片（此时无网络）
3. **TLS + 目标守卫** — `tls.rs` / `target.rs`，含单元测试
4. **JIRA 客户端与 10 个工具** — 先 `connection_status` 打通链路，再铺其余
5. **CRM 客户端与 10 个工具** — 会话缓存与重登
6. **接入 MCP 路由与审计** — `mcp.rs` 改动
7. **前端完善** — 测试连接按钮、错误提示、内网风险告知
8. **文档与 README**

## 9. 测试

**Rust 单元测试**（`cargo test`，不碰网络）
- 默认策略全关；总开关关闭时工具拒绝执行
- 主机白名单：非白名单主机拒绝；总开关关闭时内网地址拒绝
- IP 钉住：解析结果被改写时不放行
- JQL 拼装与转义；CRM SQL 转义与 `limit` 夹取
- 响应 DTO 映射与字段截断
- 脱敏：密码 / AccessKey / sessionName 不出现在输出中
- 会话缓存过期后重登一次
- ClientCert 条目的存取与备份往返

**人工联调**（UI 上的「测试连接」按钮，用户主动触发）
- JIRA `serverInfo` + CRM `getchallenge`，验证 CA、客户端证书、账号三段链路

## 10. 明确不做

- 不移植 `configure`（写凭证）
- 不移植 `insecureSkipTlsVerify`（跳过 TLS 校验）
- 不实现对外（非回环）监听、远程访问、团队共享
- 不支持任意 URL / 方法 / 请求头 / 请求体
- 不修改源插件目录
- 不在磁盘上落任何明文凭证

## 11. 后续可做（本期不做，但接口留得住）

- 把内网主机做成"用户可增删的白名单"，支持接入更多内网系统
- 工具分组按需开启，降低 `tools/list` 的 token 开销（20 个工具的 schema 约 4k token）
- 只读模式：`zoomkey_crm_query` 走 SQL 语法白名单而非放行整串
