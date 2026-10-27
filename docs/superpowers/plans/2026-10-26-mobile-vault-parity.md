# Mobile Vault Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (用户已选择) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Windows 与 Android 共用完整备份、CSV 和安全同步核心，补齐移动适配、组织管理与字段保真，通过同轮双端验证。

**Architecture:** 从桌面抽取 bytes-in/bytes-out 的 backup/CSV 到 core；core 管校验、事务、修订与条件同步，桌面管路径，Android 管 SAF 流。先冻结核心契约，再接命令和 UI；新库先校验后生成临时库、最后平台发布；同步预览只读、提交唯一对象整体 CAS。

**Tech Stack:** Rust、rusqlite、serde、Argon2/AES-GCM、ureq；Tauri 2、Vue 3/TypeScript；Android Kotlin/ContentResolver；Rust 单测、Node 内置测试。

---

## 边界与执行顺序

依据：[已批准设计](../specs/2026-10-26-mobile-vault-parity-design.md)。本文件仅是计划，以下步骤**尚未实施或验证**。规划者仅写本文件，不改设计/业务、不 Git、不测试/构建、不子委派。

- 保留另一会话最新变更、dirty 版本字段、`dist/`、`apps/mobile/dist/`、`.preview/`；开发期间不改版本、不覆盖产物、不清理无关文件。不另建 workflow，不发布。
- **Lead 最新授权收尾例外：** 等另一会话提交/构建完成，验收通过后统一全部9处版本为 `0.11.0`。最终 Git 写操作仅 Lead 经 Sealbox MCP；不打 tag、不发布。用户允许继续当前工作区，已选择子代理开发，无需再次询问方式。
- 共享任务顺序：`task-1`（阶段1、独占 core backup/CSV/vault/lib 与桌面 re-export）→ `task-2`（阶段2、sync/vault/db）→ `task-3`（阶段3/4，执行时拆平台和 UI）。`vault.rs/db.rs` 始终由单一 worker 顺序实现；sync 额外 vault 扩展先向 Lead 协调。平台 `commands.rs/lib.rs` 同样避免并行编辑。
- 每任务按“补失败测试 → **Lead** 运行确认 RED → 最小实现 → **Lead** 运行确认 GREEN → Lead 审阅差异”。下文命令均为 Lead 后续执行，不是本计划已执行的结果。不要求实现 worker 自行提交。

## 阶段1：Core backup / CSV

### Task 1：版本化 bundle、旧 SBOX1 与事务恢复

**Files:** Create `crates/sealbox-core/src/backup.rs`、`crates/sealbox-core/tests/backup_parity.rs`、`crates/sealbox-core/tests/data/legacy-sbox1.svbak`；Modify `crates/sealbox-core/src/lib.rs`、`vault.rs`、`db.rs`。从 `src-tauri/src/backup.rs` 抽取；`src-tauri/src/lib.rs` re-export core backup，旧函数暂留薄 wrapper 直到阶段4接线。若数据库序列化需要，仅调整 `crates/sealbox-core/Cargo.toml` 的 rusqlite feature，不改版本。

- [ ] **1.1 补 RED 测试。** 迁移现有 backup 的 KDF/证书/folder 映射测试；用迁移前 writer 固定合成 SBOX1 夹具，不用新版 writer 冒充旧兼容。新增下列 API 测试：

```rust
use sealbox_core::{backup, vault::Vault};
#[test]
fn malformed_backup_fails_before_new_vault_creation() {
    assert!(backup::inspect_bundle(b"SBOX1{}", "backup password long").is_err());
}
#[test]
fn optional_settings_never_transfer_sync_credentials() {
    let (src, dek) = Vault::create_in_memory("source password long").unwrap();
    src.set_setting("idle_secs", "90").unwrap();
    src.set_setting("sync_secret", "not-transferable").unwrap();
    let bytes = backup::export(&src, &dek, "source password long",
        backup::ExportOptions { include_settings: true }).unwrap();
    let bundle = backup::inspect_bundle(&bytes, "source password long").unwrap();
    let (dst, key) = Vault::create_in_memory("target password long").unwrap();
    backup::restore_into(&dst, &key, bundle,
        backup::RestoreOptions { overwrite: false, restore_settings: true }).unwrap();
    assert_eq!(dst.get_setting("idle_secs").unwrap().as_deref(), Some("90"));
    assert!(dst.get_setting("sync_secret").unwrap().is_none());
}
```

- [ ] **1.2 固定并实现契约。** `ValidatedBundle` 私有字段保存校验后的 payload/source DEK，不可序列化或 Debug；只把 summary 交 JS。新库源密码只用于 inspect，restore_new 的 password 为**新库主密码**。

```rust
pub struct ExportOptions { pub include_settings: bool }
pub struct RestoreOptions { pub overwrite: bool, pub restore_settings: bool }
pub fn inspect_bundle(bytes: &[u8], password: &str) -> Result<ValidatedBundle, VaultError>;
impl ValidatedBundle { pub fn summary(&self) -> &BackupSummary; }
pub fn export(vault: &Vault, dek: &[u8; 32], password: &str,
    options: ExportOptions) -> Result<Vec<u8>, VaultError>;
pub fn restore_into(vault: &Vault, dest_dek: &[u8; 32], bundle: ValidatedBundle,
    options: RestoreOptions) -> Result<RestoreReport, VaultError>;
pub fn restore_new(bundle: ValidatedBundle, password: &str)
    -> Result<PendingRestore, VaultError>;
impl PendingRestore {
    pub fn into_database_bytes(self) -> Result<Vec<u8>, VaultError>;
}
```

`BackupSummary`：format_version、entry_count/folder_count/tag_count、has_tombstones、settings_keys、warnings；`RestoreReport`：inserted/updated/skipped/repaired_references 数量与无秘密 warnings。`PendingRestore` 是已验证的内存临时库/新 DEK，drop 清密钥；bytes 输出由平台写临时文件，core 不接路径/URI。新库默认应用已校验白名单设置，无设置时本机默认。

- [ ] **1.3 最小实现。** 新 magic 固定 `SBOX2`、format_version=2；KDF、payload 长度/计数必须受认证或在已认证 payload 中重复核验。仅 SBOX1 magic 走旧解码，未知版本提示升级；KDF bounds 在派生前检查。解密后完整校验 schema/kind、secret/notes 密文、证书链/私钥配对、长度/计数/引用，失败零写。八类 SecretPayload 与 BackupEntry 原始全部字段保留，不经 DTO 重建。snapshot 新增 serde-default 墓碑与可选设置；只接受 `idle_secs >= 30`、`clipboard_secs 5..=120`，非法/溢出拒绝；设备身份/指纹、审计、热键、MCP、同步凭据、附件全部排除。
- [ ] **1.4 单事务恢复。** 墓碑先导入再应用；folder 同名复用与 ID 映射重写 entry 引用，**墓碑必须使用同一 ID 映射或稳定恢复原 ID**，不能 ensure_named 改 ID 后误删。显式遍历 snapshot.tags 恢复独立空标签（当前实现只遍历 entry.tags）；tag 按名称及名称墓碑去重。同 ID overwrite=false 跳过；true 替换可恢复字段。新格式非法引用整批拒绝；旧缺失引用转未分类/去失效 tag 并报告。八类、回收站/墓碑、元数据/备注、设置同事务提交，第二条损坏也整批回滚。
- [ ] **1.5 Lead 验证：** `cargo test -p sealbox-core --test backup_parity`、`cargo test -p sealbox-core backup`。预期先缺 API/行为为 RED，完成后 PASS。必须断言八类逐字段往返、证书与口令、空标签/墓碑、folder ID 映射、错误密码/KDF/截断/计数/引用失败零修改；新库路径失败断言由阶段3补。

**Acceptance:** 读旧写新、八类与完整元数据可恢复；不改目标主密码/排除设置，不部分导入，不复活已删除对象。

### Task 2：CSV bytes API 与网站导出

**Files:** Create `crates/sealbox-core/src/csv.rs`、`crates/sealbox-core/tests/csv_parity.rs`；Modify `crates/sealbox-core/src/lib.rs`、`src-tauri/src/lib.rs`（re-export）。从 `src-tauri/src/csv_import.rs` 抽取解析/识别/校验/去重策略，identity 用已有 core identity，不依赖桌面 fill；路径 wrapper 留到阶段4替换。

- [ ] **2.1 补 RED，迁移四种格式测试。** 新增以下往返测试，另覆盖无效 UTF-8、未闭合引号/引号后非法字符、BOM 只剥一次、CRLF/LF/中文/逗号/双引号、空密码有 TOTP、5MiB/5000行及现有字段上限。

```rust
use sealbox_core::{csv, vault::{ListFilter, SecretPayload, Vault}};
#[test]
fn formula_password_survives_csv_roundtrip() {
    let input = "\u{feff}title,url,username,password,totp,notes,tags\r\n\
中文,https://example.test,u,\"=SUM(1,1)\",,\"第一行\n第二行\",标签\r\n";
    let (v, d) = Vault::create_in_memory("csv password long").unwrap();
    let prepared = csv::preview(input.as_bytes(), None).unwrap();
    let shown = serde_json::to_string(&prepared.summary(&v, &d).unwrap()).unwrap();
    assert!(!shown.contains("=SUM"));
    assert!(shown.contains("has_password"));
    csv::commit(&v, &d, prepared, false).unwrap();
    let bytes = csv::export_websites(&v, &d).unwrap();
    let (out, key) = Vault::create_in_memory("other password long").unwrap();
    csv::commit(&out, &key, csv::preview(&bytes, None).unwrap(), false).unwrap();
    let rows = out.list_entries(&ListFilter::default()).unwrap();
    match out.get_secret(&key, &rows[0].id).unwrap() {
        SecretPayload::Website { password, .. } => assert_eq!(password, "=SUM(1,1)"),
        _ => panic!("website expected"),
    }
}
```

- [ ] **2.2 实现唯一契约。** PreparedCsv 私有 rows、不可序列化，commit 按值消费；summary 用目标库计算重复统计，commit 在事务中重查。不能接前端自造 rows，也不在 commit 重新读可能被替换的源路径。

```rust
pub fn preview(bytes: &[u8], format_hint: Option<CsvFormat>) -> Result<PreparedCsv, CsvError>;
impl PreparedCsv {
    pub fn summary(&self, vault: &Vault, dek: &[u8; 32]) -> Result<CsvPreviewSummary, CsvError>;
}
pub fn commit(vault: &Vault, dek: &[u8; 32], rows: PreparedCsv, overwrite: bool)
    -> Result<CsvCommitReport, CsvError>;
pub fn export_websites(vault: &Vault, dek: &[u8; 32]) -> Result<Vec<u8>, CsvError>;
```

summary 固定 format/total/importable/skipped_existing/skipped_invalid/sample，样例仅脱敏 title/url/username 与 has_password/has_totp；报告固定 format/inserted/updated/skipped/invalid。导出仅有效网站，固定 `title,url,username,password,totp,notes,tags`、UTF-8 BOM/CRLF、RFC4180 escaping，公式前缀不改写；不带其他类型/回收站/设置/墓碑。错误/日志不含原始错误行或秘密。
- [ ] **2.3 Lead 验证：** `cargo test -p sealbox-core --test csv_parity`（RED→PASS）。二次验密、风险确认、preview token 消费由平台实现。

**Acceptance:** 四格式可识别、预览脱敏、密码/TOTP/备注往返；CSV 不冒充完整备份。

## 阶段2：Core sync 预览、条件 PUT 与分类防复活

### Task 3：vault 修订、presence patch 与组织事务

**Files:** Modify `crates/sealbox-core/src/vault.rs`、`db.rs`；Create `crates/sealbox-core/tests/vault_parity.rs`。此任务先于 sync、单 worker 持有写域。

- [ ] **3.1 补 RED 测试，随后实现签名。** Revision 为本地单调 u64，不用 updated_at 冒充。迁移幂等；所有参与同步的 entry/folder/tag/墓碑写事务 bump 一次，失败不 bump；audit/sync 配置不制造同步循环，backup 不覆写目标 revision。

```rust
pub type Revision = u64;
pub type EntryPatch = std::collections::BTreeMap<String, serde_json::Value>;
impl Vault {
    pub fn revision(&self) -> Result<Revision, VaultError>;
    pub fn entry_revision(&self, id: &str) -> Result<Revision, VaultError>;
    pub fn patch_entry(&self, dek: &[u8; 32], id: &str, patch: EntryPatch,
        expected_revision: Revision) -> Result<EntryDto, VaultError>;
    pub fn repair_organization_refs(&self) -> Result<usize, VaultError>;
}
pub fn server_protocols() -> &'static [&'static str]; // ssh/rdp/sftp/ftp/vnc
pub fn database_engines() -> &'static [&'static str]; // 从桌面当前选项抽为唯一来源
```

EntryPatch 缺 key=保留、null=显式清允许为空的字段；secret 对当前 kind 已知字段递归 presence 更新；禁止修改 id/kind/修订/计数/时间戳，未知键报错。仅 protocol/engine 保留未知字符串，不承诺未来 JSON 字段。EntryProfile 增加 revision。

```rust
#[test]
fn rejected_patch_does_not_bump_revision() {
    use sealbox_core::vault::{EntryPatch, Vault};
    let (v, d) = Vault::create_in_memory("patch password long").unwrap();
    let before = v.revision().unwrap();
    let patch: EntryPatch = serde_json::from_str(r#"{"title":"new"}"#).unwrap();
    assert!(v.patch_entry(&d, "missing", patch, before).is_err());
    assert_eq!(v.revision().unwrap(), before);
}
```

- [ ] **3.2 复用现有 rename/delete/merge。** 删除只解关联、不删 entry；合并去重保目标 ID。tag 墓碑 kind=`tag`、id=名称，rename/merge 给源名称留墓碑；folder 沿用 ID。导入/组织/sync 落库同事务修复失效引用，但不能用修复放宽新版 bundle 校验。保留现有墓碑保留期，不静默缩短；显式恢复才解除删除语义。
- [ ] **3.3 Lead 验证：** `cargo test -p sealbox-core --test vault_parity`（RED→PASS），覆盖分类删/合不删条目、空标签、名称墓碑、标题-only patch 保留 expires_at/mailbox/SSH、未知协议/引擎、旧 revision 拒绝。**已有 change_master_password 不重写。**

**Acceptance:** 单一修订/事务入口、分类墓碑跨备份和同步防复活、隐藏字段不覆空。

### Task 4：sync runtime、强 ETag/CAS 与结构化报告

**Files:** Modify `crates/sealbox-core/src/sync.rs`；Create `crates/sealbox-core/src/sync/tests.rs`（cfg(test) 子模块）。额外 vault/db 需求先给 Lead，不擅自扩大写域。

- [ ] **4.1 补 RED mock 测试后实现契约。** 附录接口追加显式 runtime 参数以承载会话、token、同步锁，不使用全局 token 表；两端各 AppState 一份，前后台共用。

```rust
pub struct RemoteObject { pub body: Vec<u8>, pub etag: String }
pub enum PutCondition { IfMatch(String), IfNoneMatchStar }
pub trait RemoteStore: Send + Sync {
    fn get(&self) -> Result<Option<RemoteObject>, SyncError>;
    fn put(&self, body: &[u8], condition: PutCondition) -> Result<String, SyncError>;
}
impl SyncRuntime {
    pub fn new(store: Box<dyn RemoteStore>) -> Self;
    pub fn invalidate(&self);
}
pub fn preview(vault: &Vault, dek: &[u8; 32], runtime: &SyncRuntime)
    -> Result<SyncPreview, SyncError>;
pub fn commit(vault: &Vault, dek: &[u8; 32], runtime: &SyncRuntime,
    token: &str, choices: &[ConflictResolution]) -> Result<SyncReport, SyncError>;
```

SyncPreview 固定 token/local_revision/etag/expires_at/actions/conflicts；action=`local/remote/both/unchanged`。ConflictResolution 固定 conflict_id/choice/confirm_restore/confirm_delete，choice=`local/remote/both`，两个 bool 对 delete-vs-edit 生效。冲突项含 entry/folder/tag 类型与 delete-vs-edit 标记。SyncReport 固定 phase/etag/pulled/pushed/unchanged/removed/conflicts/blocked_reason/retryable，conflicts 是结构体数组；phase 按设计附录D。持久化只存计数/phase/阻塞码，不存标题、用户名、URL/秘密。

```rust
#[test]
fn missing_preview_never_writes() {
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    struct Store(Arc<AtomicUsize>);
    impl RemoteStore for Store {
        fn get(&self) -> Result<Option<RemoteObject>, SyncError> { Ok(None) }
        fn put(&self, _: &[u8], _: PutCondition) -> Result<String, SyncError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok("\"etag-1\"".into())
        }
    }
    let writes = Arc::new(AtomicUsize::new(0));
    let runtime = SyncRuntime::new(Box::new(Store(writes.clone())));
    let (v, d) = Vault::create_in_memory("sync password long").unwrap();
    assert!(commit(&v, &d, &runtime, "not-a-preview", &[]).is_err());
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}
```

- [ ] **4.2 最小实现 CAS。** WebDAV/S3 现有唯一对象用强 ETag `If-Match`，缺失用 `If-None-Match: *`；S3 签名覆盖条件头。缺强 ETag/条件能力即 blocked，不能只以前置 GET/OPTIONS 当 CAS。对未知 provider 用隔离随机探测对象验证错误条件被拒且内容不变，验证不了 fail closed；探测不写金库对象，清理失败明确报告。
- [ ] **4.3 实现固定提交顺序。** runtime 操作锁覆盖 preview→网络→本地提交；会话 generation/取消标记检查 unlock，token 最长10分钟。核对本地 revision、重读 ETag、校验全部 choices，再对唯一对象**一次整体条件 PUT**；不能先提交无冲突项。成功后本地事务再比 revision、原子提交 snapshot+墓碑。412/stale 不落本地；PUT成功/本地失败保留内存合并快照和返回 ETag，重试先核对远端而非盲目重 PUT；lock/timeout/进程异常清 token/选择/明文，重启重新预览。不长持 UI session mutex。
- [ ] **4.4 实现选择与自动同步。** both 保本机原 ID，另建可区分新 ID 的远端/编辑副本；删除对编辑保原墓碑、编辑副本新 ID，恢复/删除分别要求显式确认。分类同样参与防复活。自动同步任意冲突整次暂停并通知，零冲突且 CAS成功才提交；旧 sync_now 仅可安全包装两阶段，移除无条件路径。不宣称识别所有无修订的异步编辑。
- [ ] **4.5 Lead 验证：** `cargo test -p sealbox-core sync`（RED→PASS），mock 断言 preview零写/创建条件/强弱ETag/412/提交至多一次整体PUT/本地revision改变/lock/超时/三种选择/分类墓碑/自动同步整次暂停/网络成功本地失败可恢复。

**Acceptance:** 手动与自动入口无 CAS 旁路，失败两端数据仍在，冲突必须逐条处理。

## 阶段3：移动 SAF 与 Rust 命令

### Task 5：可再生成的 SAF stream bridge

**Files:** Create `src-tauri-mobile/src/saf.rs`、`src-tauri-mobile/android/SafBridge.kt`（维护模板）、`scripts/patch-mobile-android.test.mjs`；Modify `src-tauri-mobile/src/lib.rs`、`scripts/patch-mobile-android.mjs`；必要时 `src-tauri-mobile/Cargo.toml` 仅 JNI 依赖、不改版本。脚本生成 `src-tauri-mobile/gen/android/app/src/main/java/com/sealbox/mobile/SafBridge.kt` 并幂等注册同目录 MainActivity.kt，不能只手改 gen（现有 release 会重建工程）。

- [ ] **5.1 RED 测试再实现。** patch 脚本提取可导入纯函数，import 无真实目录副作用；Node 临时目录测试应用两次只注册一次、保留 activity 已有内容、模板复制一致。
- [ ] **5.2 冻结流接口。** Kotlin Activity Result 调 ACTION_OPEN_DOCUMENT/ACTION_CREATE_DOCUMENT；URI opaque，ContentResolver 流限量读取、写后关闭并读回长度/摘要验证；finally关闭流，取消单独返回。Rust cfg(android) JNI 接桥，host 用 fake。

```rust
pub trait DocumentIo {
    fn read(&self, uri: &str, max_bytes: usize) -> Result<Vec<u8>, SafError>;
    fn write_new(&self, uri: &str, bytes: &[u8]) -> Result<(), SafError>;
}
// Kotlin: fun read(uri: String, maxBytes: Long): ByteArray
// Kotlin: fun writeNew(uri: String, bytes: ByteArray)
```

- [ ] **5.3 实现失败策略。** 不将 content URI 转路径、不用浏览器下载。输出先验密/生成，再创建新文档；provider无原子rename则用户确认替换，不伪装原子。取消/拒权零写库；写中断提示文件选择器清半成品、不覆盖旧备份。
- [ ] **5.4 Lead 验证：** `node --test scripts/patch-mobile-android.test.mjs`、`cargo test -p sealbox-mobile saf`（RED→PASS），真机非路径provider/取消/拒权/中断归阶段5。

**Acceptance:** Android工程重生成仍带bridge，SAF从不假定真实文件路径。

### Task 6：移动命令、新库发布与改密 adapter

**Files:** Create `src-tauri-mobile/src/transfer.rs`；Modify `src-tauri-mobile/src/commands.rs`、`lib.rs`、`session.rs`、`auto_sync.rs`；测试放相应模块 cfg(test)。

- [ ] **6.1 RED 命令/helper 测试，然后接唯一契约。** 以下为业务参数→结果，实际命令另加 AppHandle/State 注入；Tauri 参数 camelCase，DTO 字段保持 core snake_case。

```rust
backup_inspect(uri: String, backup_password: String) -> BackupInspection // token+summary
backup_restore(token: String, options: RestoreOptions) -> RestoreReport
backup_restore_new(token: String, new_password: String) -> RestoreReport
backup_export(uri: String, password: String, options: ExportOptions) -> ()
csv_preview(uri: String, format_hint: Option<CsvFormat>) -> CsvInspection // token+summary
csv_commit(token: String, password: String, risk_confirmed: bool, overwrite: bool) -> CsvCommitReport
csv_export(uri: String, password: String, risk_confirmed: bool) -> ()
change_master(old_password: String, new_password: String) -> ()
patch_entry(id: String, patch: EntryPatch, expected_revision: Revision) -> EntryDto
sync_preview() -> SyncPreview
sync_commit(token: String, choices: Vec<ConflictResolution>) -> SyncReport
entry_options() -> EntryOptions // server_protocols/database_engines
```

已存在的 folder rename/delete 命令保留，新增 merge_folders/rename_tag/delete_tag/merge_tags，与 core 现有参数一致。所有 command 除无库 inspect/new 外要求解锁；新库 token 与目标存在性再检查。CSV token持有 PreparedCsv，10分钟/lock/消费后销毁；commit/export二次验密和风险确认均强制。摘要不回 secret。
- [ ] **6.2 先校验、再临时库、最后发布。** inspect 完整通过才 restore_new；平台 helper `publish_new_database(bytes: &[u8], dest: &Path, password: &str) -> Result<(), String>`：同卷 std 唯一临时文件→flush→打开验证新密码/首条密文（空库验DEK）→checkpoint/关闭含WAL→原子发布。目标已存在拒绝，失败只清本次临时库/sidecar，不动现有库；不用引入 tempfile。

```rust
#[test]
fn malformed_new_database_leaves_no_destination() {
    let dir = std::env::temp_dir().join(format!("sealbox-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let dest = dir.join("vault.db");
    assert!(publish_new_database(b"broken sqlite", &dest, "new password long").is_err());
    assert!(!dest.exists());
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir(&dir).unwrap();
}
```

- [ ] **6.3 仅 adapter 复用已有改密。** 调 `Vault::change_master_password(&dek, &old, &new)`，不重写 KDF/rewrap、不重加密 secret；主密码不进同步。Rust证书导入读SAF后验证配对，私钥不回显，无替换选项保留原证书。锁定/idle清transfer与sync runtime；自动同步改安全两阶段。指纹失败先清session DEK，再清本地biometry存储，完成后才允许再授权；失败一律回主密码。
- [ ] **6.4 Lead 验证：** `cargo test -p sealbox-mobile`（RED→PASS），覆盖坏文件不留空库/不覆盖现有库、验密失败零写、lock token失效、改密DEK/entry密文不变、指纹失败无可用DEK。

**Acceptance:** 无库可直接恢复，命令注册齐全；改密不重复实现，证书不泄漏。

## 阶段4：Desktop 接入与两端 UI

### Task 7：桌面 core 接线与安全输出

**Files:** Modify `src-tauri/src/backup.rs`、`csv_import.rs`（仅I/O wrapper）、`commands.rs`、`lib.rs`、`session.rs`、`auto_sync.rs`；Create `src-tauri/src/transfer.rs`（临时文件/token，内嵌测试）。

- [ ] **7.1 RED adapter测试，随后迁移命令。** 与Task6同名/DTO/业务参数，仅 uri→path；移除能绕preview/验密的旧invoke入口，前端同轮迁移。不留第二份CSV/backup逻辑；preview读一次bytes，commit消费已验证对象，不重读路径。
- [ ] **7.2 最小I/O实现。** `write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String>`：同目录临时文件、write_all/flush/sync_all、平台安全替换；失败保旧目标，提示临时文件名“请清理临时文件并重试”，不自动打开/上传。注入write/rename失败测试核对旧内容未变。CSV导入/导出二次验密+风险确认，backup导出验密；lock/timeout销毁token；前后台共用SyncRuntime，不影响现有扩展/MCP/更新。
- [ ] **7.3 Lead 验证：** `cargo test -p sealbox`（RED→PASS）；原SBOX1测试迁core保留，不删测试过关。

**Acceptance:** 桌面与Android同一核心，路径输出失败不伤旧文件，无无条件同步旁路。

### Task 8：两端 UI、组织管理、编辑保真、逐条冲突

**Files:** Modify `apps/mobile/src/api.ts`、`apps/mobile/src/App.vue`、`src/lib/tauri.ts`、`src/App.vue`；Create `apps/mobile/src/entry-patch.mjs`、`entry-patch.d.mts`、`entry-patch.test.mjs`；Create `src/lib/sync-choice.mjs`、`sync-choice.d.mts`、`sync-choice.test.mjs`（纯helper，移动相对导入，不加测试框架）。

- [ ] **8.1 RED纯函数测试，再实现。** `buildEntryPatch(before, after)` 只输出用户编辑的已定义字段，secret递归presence；`canCommit(conflicts, choices)` 必须每条选择完整且confirm_restore/confirm_delete符合删除边界。

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildEntryPatch } from './entry-patch.mjs';
test('title-only edit preserves hidden fields', () => {
  const before = { title: 'old', expires_at: '2030-01-01',
    secret: { type: 'ssh', key_type: 'ed25519', passphrase: 'keep' } };
  assert.deepEqual(buildEntryPatch(before, { title: 'new' }), { title: 'new' });
});
```

- [ ] **8.2 API与编辑接线。** core DTO/enum不另命名；EntryProfile revision用于patch_entry expectedRevision，旧修订提示刷新、不静默覆盖。创建仍UpsertEntry。补expires_at、mailbox imap/smtp、SSH key_type/passphrase/fingerprint字段；未呈现字段不发null/空串；协议/引擎由entry_options供给，未知原值可选可保存、不强制默认。
- [ ] **8.3 转移/组织/改密UI。** 首次页直接“从备份恢复”不先setup；摘要/恢复设置开关/新版升级提示。CSV预览后验密+主动确认，固定文案“CSV 是明文文件，建议导入后立即删除源文件”，说明排除内容与公式注入取舍、值不改写。移动只用SAF；证书私钥不展示。组织入口显示空标签，rename/delete/merge确认并刷新筛选；删除不删entry，撤销提示明确重新关联/恢复方式，不假称自动撤销。改密成功/失败与指纹回退按Task6顺序。
- [ ] **8.4 同步UI。** 逐条local/remote/both；delete/edit显示恢复或删除二次确认，缺项禁提交。自动同步暂停通知；stale重新preview；lock/timeout清token/选择/待选数据；网络错误可重试；缺强ETag/CAS显示blocked，不提供强制无条件覆盖。
- [ ] **8.5 Lead 验证：** `node --test apps/mobile/src/entry-patch.test.mjs src/lib/sync-choice.test.mjs`（RED→PASS）；类型/前端构建归阶段5双端同轮。移动必须Tauri Android运行时/真机，普通浏览器invoke失败不是移动验证。

**Acceptance:** 所有流程走冻结契约，隐藏字段/未知值保真，未确认冲突不能写。

## 阶段5：Lead 两端联合验证与收尾

### Task 9：完整闸门、0.11.0与同轮打包

**Files:** Create `docs/tests/2026-10-26-mobile-vault-parity-validation.md`（Lead后续记录真实结果，无秘密）。最终单独窗口Modify：`package.json`、`package-lock.json`（根与packages[""].version）、`src-tauri/Cargo.toml`、`src-tauri/tauri.conf.json`、`extension/manifest.json`、`Cargo.lock`的sealbox/sealbox-mobile、`src-tauri-mobile/Cargo.toml`、`src-tauri-mobile/tauri.conf.json`；按现有脚本全部9处口径统一0.11.0，不改core独立版本。

- [ ] **9.1 等另一会话收尾、Lead核对基线。** 保留其提交/dirty，验证在Lead准备的隔离副本执行，不覆盖原dist/.preview或另一会话制品。
- [ ] **9.2 Lead执行完整测试，记录实际exit code。** 任一失败停止交付，修复后重跑受影响测试与完整闸门；下列均预期exit0，未执行不得勾通过。

```bash
cargo test -p sealbox-core
cargo test --manifest-path src-tauri/Cargo.toml
cargo test --manifest-path src-tauri-mobile/Cargo.toml
node --test extension/fill-logic.test.js src/lib/audit-request.test.js
node --test scripts/patch-mobile-android.test.mjs apps/mobile/src/entry-patch.test.mjs src/lib/sync-choice.test.mjs
npm run build && npm run mobile:build
```

- [ ] **9.3 两端交叉验收。** 桌面导出→Android无库恢复→Android导出→桌面恢复，八类/私钥口令/TOTP/备注/元数据/回收站/folder ID/空tag/墓碑逐字段核对；旧SBOX1与所有坏输入不留空库；SAF非路径provider/取消/拒权/中断；CSV中文换行/BOM/引号/公式密码；改密旧失败新成功且DEK/密文不变、指纹撤销回退；分类不删entry、隐藏字段/未知值保真；两设备412/删除编辑三选/分类防复活/自动同步暂停/lock与10分钟过期/PUT成功本地失败恢复，均记录设备与结果。
- [ ] **9.4 验收通过并释放版本写域后，Lead统一0.11.0。** `node scripts/check-version.mjs v0.11.0` 必须exit0，随后重跑9.2；不得在开发期间先改版本。
- [ ] **9.5 同轮同最终源码版本完整打包Windows与Android。** 隔离副本Windows根目录 `npm run tauri -- build`；配置好Java/SDK/NDK的移动环境、工作目录`src-tauri-mobile`执行 `npx tauri android build --ci --apk --target aarch64`。需重生工程时沿用现有init与`node scripts/patch-mobile-android.mjs`，保留SAF模板。环境缺失向Lead报具体依赖，不以只做单端降级完成。记录Windows安装包/arm64 APK路径和摘要、安装验证；任一端失败则整轮未完成。**前端build不等于完整打包。** 不触发release workflow，不上传Release。
- [ ] **9.6 Lead最终差异审查，仅Sealbox MCP提交获准改动。** 不stage无关dirty，不覆盖旧产物，不打tag、不发布、不加workflow；交付报告列真实测试/制品/阻塞，worker不直接git操作。

**Final Acceptance:** 核心/desktop/mobile/extension测试与两端前端构建通过，同轮Windows安装包和Android APK均验证，全部9处版本0.11.0一致；保留原会话变更/dirty/产物，无新增发布入口或Release。任何未执行项明确标注“未执行”，计划不是完成证据。

## 接口交接摘要

- backup：bytes→ValidatedBundle（只公开summary）→事务restore_into或PendingRestore→数据库bytes→平台发布；SBOX1读兼容、SBOX2写新版。
- CSV：bytes→PreparedCsv→脱敏summary→token消费commit；export_websites→bytes；密码/TOTP不经过预览DTO。
- sync：同一SyncRuntime持token/锁/10分钟内存快照；preview→逐条ConflictResolution→唯一对象一次条件PUT→本地revision事务。
- vault：复用已有change_master_password；新增Revision/presence patch与组织引用修复，core单worker顺序扩展。两端仅adapter，不自造第二份加密/解析逻辑。
