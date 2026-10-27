# 移动端金库能力对齐设计

日期：2026-10-26  
状态：范围已确认，详细设计待评审

## 1. 目标与边界

用户已批准共用金库核心，并由桌面与 Android 做平台适配。本设计补齐移动端备份、CSV、改主密码、组织管理、条目编辑与安全同步；不改变发布入口，不改版本号，不发布，不触碰已有 dirty `dist/` 与 `.preview/`。

设计依据：`backup.rs`/`csv_import.rs` 目前是桌面私有；核心 `BackupSnapshot` 只有 folders/tags/entries，但 `SecretPayload` 已包含证书、私钥、口令；手机没有 backup/CSV/change_master 命令；手机已有文件夹增删改名但入口不足，标签只有读取；同步在同一 `updated_at` 内容不同时保留本机后立即无条件 PUT，报告为字符串；手机编辑会把 `expires_at` 写成 null，mailbox 高级字段和 SSH 类型也可能被空值覆盖。

非目标：不迁移附件、设备身份/指纹/热键/MCP 授权/同步凭据，不同步主密码，不把 CSV 当作完整备份，不声称能识别所有并发异步编辑，也不以旧版前置 GET 冒充 CAS。

## 2. 核心数据与模块边界

### 2.1 Backup bundle

在 `sealbox-core` 新建 `backup` 模块，桌面与移动只负责字节来源/去向、密码确认和 UI。旧 `SBOX1` `.svbak` 保持可读；新格式使用版本化 bundle：固定 magic、format_version、KDF 参数、加密 payload、校验长度和条目计数。解密后必须先完成 schema、枚举、引用、密文可解、证书链/私钥配对和计数校验，再允许导入。

payload 明确包含八类可恢复内容：网站/TOTP、API token、SSH 私钥及 passphrase、邮箱及高级字段、邮箱认证、服务器、数据库、客户端证书私钥及 passphrase；另含备注、普通元数据、回收站状态、分类（folder）、标签、同步墓碑。不要只从 DTO 重建，保留 `created_at/updated_at/deleted_at/use_count/last_used_at/pinned/expires_at/fingerprint` 等字段。

folder 沿用现有 ID 映射与同名复用语义；tag 不新增稳定 ID 模型，沿用名称语义和名称墓碑。entry 的 folder/tag 引用按现有规则导入，不能因名称误挂；独立空标签恢复，墓碑先导入再应用，避免已删除条目复活。新格式引用非法时拒绝整个导入；旧备份历史缺失引用可转为未分类，并在恢复报告中说明。

设置仅白名单恢复：可选 `idle_secs`、`clipboard_secs`，按合法范围校验后写入；审计、设备身份/指纹、热键、MCP 授权、同步凭据一律跳过。不迁移附件，也不新增附件字段。

### 2.2 导入事务与平台 I/O

Core 提供 `inspect_bundle`、`restore_into(vault, options)` 和 `restore_new`。新手机入口无需先建库：读取完整 bytes，校验通过后在临时数据库和临时 DEK 中创建金库，最后以原子替换/提交发布；任何密码错误、截断、计数不符、引用不符或证书校验错误都不得留下空库。

桌面导出写临时文件、flush、rename；导出中断展示“请清理临时文件并重试”。Android 不假定 SAF `content://` 是路径，使用原生 Storage Access Framework 的 `ContentResolver` 流读写；provider 不承诺原子 rename 时不伪装原子，采用新文档写完后校验、再由用户确认替换，失败提示清理半成品。不得调用浏览器下载模拟导出。

Android Rust command 接受 opaque content URI，通过 Kotlin/Java SAF bridge 获取输入输出流。证书导入在 Rust 读取并校验证书与私钥对应、私钥不得回显；已有证书无替换选项时保持不变。桌面路径适配与 mobile SAF 适配不能进入 core。

## 3. CSV 明文迁移

把 `csv_import.rs` 的解析、格式识别、行校验、预览模型、提交策略移入 core，并新增网站专用导出。CSV 是明文迁移，不包含 SSH、证书、服务器/数据库高级字段、回收站、审计、同步墓碑或设置；导入导出界面必须写明这一取舍。

输入输出遵循 RFC 4180：UTF-8，可识别/生成 BOM，CRLF 与 LF 均可读，字段含逗号、引号、中文换行时双引号包裹并将引号写成 `""`。支持现有 Chrome/Bitwarden/OnePassword/Sealbox 识别；导出固定列并保证密码、TOTP、备注往返。公式注入采用“导出时给可疑首字符加单引号”的安全策略会破坏密码往返，因此默认不改字段、以明示风险确认和导出前警告承担取舍；CSV 绝不写日志秘密。

两端都必须先 `csv_preview` 再 `csv_commit`：预览仅返回格式、总行数、可导入/跳过统计和脱敏样例，不返回密码/TOTP；提交前要求主密码二次验证和“明文迁移”风险确认。移动同样用 SAF 流，不把 URI 转路径。导出也要求主密码二次验证，失败不得产生可用的半成品文件。

## 4. 主密码、组织与字段保真

复用已有 core `change_master_password`：先用旧密码解包 DEK，再以新 KDF 参数 rewrap 同一 DEK，不重加密每条 secret，不改变同步内容，也不新增撤销机制。旧密码错误或新密码不合规不写库；成功后审计只记动作与结果，不记密码。移动指纹失效、清除或重新授权失败均安全回退到主密码，清除本地 DEK 后才允许重新授权；主密码永不进入同步。

core 对 folder/tag 提供并统一两端命令：rename/delete/merge。删除只解除分类或标签关联，不删条目；合并去重关联并保留目标 ID。导入、删除、合并后都运行分类引用修复：找不到 folder 的条目归未分类，找不到 tag 的引用丢弃；同名导入按 ID 映射，避免把不同分类错误合并。手机 UI 增加组织管理入口，显示空标签并支持确认、撤销提示和刷新筛选。

编辑使用“部分更新”契约：客户端提交字段 presence map 或基于已读对象的完整保真对象；未呈现字段不得写 null/空串，必须保留当前已定义的全部隐藏字段，包括 `expires_at`、mailbox 的 imap/smtp host/port、SSH `key_type/passphrase/public_fingerprint` 等。未知值仅对 protocol/engine 保留原始字符串；不承诺未来未知 JSON 字段。服务端按 entry revision 校验，冲突时拒绝静默覆盖。

服务器协议选项统一为 `ssh/rdp/sftp/ftp/vnc`，数据库引擎选项由 core 提供并由桌面、Android 联动；UI 可展示已知值但读取未知值必须保留、可保存、不可强制归默认。

## 5. 同步安全协议

将同步拆成 `sync_preview` 与 `sync_commit` 两阶段。预览读取本地修订和远端对象及 ETag，生成逐条动作：local、remote、both、unchanged，并包含“删除对编辑”的边界；任何版本都不先丢弃。冲突 UI 逐条选择 local/remote/both，`both` 生成可区分副本或冲突记录，不能用字符串报告替代选择。

远端对象接口必须支持强 ETag、条件更新 `PUT If-Match` 和创建 `If-None-Match: *`；缺失任一能力时 fail closed，提示旧客户端或 provider 升级，禁止无条件写。一次同步只对唯一远端对象执行一次整体条件 PUT，禁止先写无冲突项再写冲突项。提交前及全过程重新核对本地 revision、同步锁和预览 token；本地 revision 防并发，网络成功但本地写事务失败时保留合并快照，支持重试恢复。

自动同步发现冲突时整次暂停写入并发通知；不自动选 LWW。自动同步只在无冲突且 CAS 成功时提交。冲突快照只存内存，最长 10 分钟；锁定、超时、进程异常、预览 token 失效均清除。报告改为结构化对象：phase、etag、pulled/pushed/unchanged/removed、conflict items、blocked reason、retryable；持久化摘要不得包含标题、用户名、URL、密码、token 或其他秘密。

同步墓碑纳入 bundle 和 sync snapshot，保留期内参与冲突判断；删除对编辑按“编辑胜出需明确恢复，删除胜出需明确确认”处理。`both` 生成新 ID 的编辑副本并保留本机原 ID；删除对编辑时保留删除标记，同时以新 ID 保存编辑副本。仍不宣称可以识别远端离线期间所有异步编辑，只能识别有修订/ETag 支持的并发。

## 6. 分阶段实现

1. **Core**：抽出 backup/CSV；扩展版本化 snapshot、设置白名单、现有 folder ID 映射与名称墓碑；复用 `change_master_password`，实现部分更新、字段保真、同步 preview/commit/ETag 抽象和结构化报告。
2. **Desktop**：接入 core backup/CSV；保留 SBOX1 读取；实现临时文件导出、密码二次确认、CAS provider 能力检测和冲突 UI，不改发布 workflow。
3. **Mobile Rust + SAF**：增加 SAF stream bridge、备份新库原子发布、证书校验、backup/CSV/change_master/组织/同步命令；指纹失败清理 DEK 并回退密码。
4. **Mobile Vue**：增加首次导入入口、预览提交流程、明文警示、组织管理、完整字段编辑、协议/引擎联动、逐条冲突选择和锁定/失败提示。

## 7. 验收矩阵

| 目标 | 桌面 | Android | 共同判定 |
|---|---|---|---|
| SBOX1 与新版 bundle | 读旧、写新 | 读旧、写新 | 八类条目、证书/私钥/口令/TOTP、备注、元数据、回收站、分类、墓碑均可往返 |
| 新手机导入 | 不适用 | 无库直接导入 | 完整校验前不建库；失败无空库；folder ID 与独立空标签正确 |
| SAF/导出中断 | 临时文件可恢复提示 | content URI 流读写 | 不把 URI 当路径，不声称 provider 原子性 |
| CSV | 预览/提交/导出 | 预览/提交/导出 | RFC4180、中文换行/BOM、密码往返、无秘密日志、二次确认 |
| 改密与指纹 | rewrap | rewrap；失败安全回退 | DEK 不变，主密码不进同步 |
| 组织/编辑 | 全量 | 全量 | 删除不删条目；未呈现字段不覆空；未知值保留 |
| 同步 | preview/commit/CAS | preview/commit/CAS | 强 ETag/条件写缺失即拒绝；唯一对象整体 PUT；冲突逐条 local/remote/both；失败可重试 |

完成验收后才允许更新两端版本字段；每次构建必须同时产出桌面和 Android，沿用 `.github/workflows/release.yml`，不新增单端 workflow、不发布 `mobile-v*`。本设计阶段不执行构建、测试、版本修改或 git 操作。

## 附录 A：核心接口契约

以下接口名称是实现边界，具体 Rust 类型应保持可序列化且跨端一致。

- `backup::inspect_bundle(bytes, password)`：只解密、校验并返回摘要。
- 摘要包含格式版本、条目数、分类数、标签数、是否含墓碑和可恢复设置键。
- 摘要不包含任何 secret、密码、TOTP、私钥或证书正文。
- `backup::export(vault, dek, password, options)`：返回完整 bundle bytes。
- `backup::restore_into(vault, dest_dek, bundle, options)`：在事务中合并到既有库。
- `backup::restore_new(bundle, password)`：返回已校验的临时库和待发布句柄。
- `csv::preview(bytes, format_hint)`：返回统计与脱敏样例。
- `csv::commit(vault, dek, rows, overwrite)`：只接受经过 preview 的行集合。
- `csv::export_websites(vault, dek)`：返回网站字段 CSV，不读取其他类型来拼列。
- `vault::change_master_password(dek, old, new)`：复用现有 core 能力，只更新 KDF 与 wrapped DEK。
- `vault::patch_entry(dek, id, patch, expected_revision)`：按 presence 更新。
- `sync::preview(vault, dek)`：返回远端 ETag、动作和预览 token。
- `sync::commit(vault, dek, token, choices)`：重新验证 revision、锁和强 ETag 后，对唯一远端对象执行一次整体条件写。

所有 command 均要求已解锁，除新库导入的“校验前阶段”外不得创建或打开目标库。

## 附录 B：恢复规则

1. bundle magic 不匹配时尝试旧 `SBOX1` 解析，不进行宽松 JSON 猜测；旧 `SBOX1` 保持可读。
2. 未知 bundle 版本返回“需要升级”错误，不按当前版本强行导入；新格式写出不保证旧应用可读，界面须提示升级。
3. KDF 参数超范围时在派生密钥前失败。
4. 解密成功但 payload JSON 不完整时视为损坏，不写目标库。
5. 条目 kind 与 SecretPayload kind 不一致时拒绝整个导入。
6. 客户端证书与私钥不匹配时拒绝整个导入。
7. 新格式缺失或非法 folder/tag 引用拒绝整个导入；旧备份历史缺失引用可转为未分类，并计入恢复摘要。
8. 旧备份历史缺失的 folder/tag 引用可转为未分类，并计入恢复摘要；新格式不以宽松修复掩盖非法引用。
9. 独立 tag 没有关联条目时仍插入 tags 表。
10. 同名 folder 复用目标 ID，按现有 folder ID 映射重写 entry 引用。
11. tag 按名称语义和名称墓碑合并，重复 entry-tag 只保留一条。
12. 同 ID 且 overwrite=false 时保留现有 entry，并报告 skipped。
13. 同 ID 且 overwrite=true 时替换可恢复字段，但不替换本机排除字段。
14. 已删除 entry 的 deleted_at 和墓碑必须按恢复选项保留。
15. 导入设置只接受 idle_secs 与 clipboard_secs，其他键全部忽略。
16. 导入不产生设备身份变化，不旋转本机指纹授权，不覆盖同步凭据。
17. 恢复完成后一次性提交事务；中途异常回滚整个批次。
18. Android 发布新库前验证临时库可用主密码打开且首条密文可解。

## 附录 C：CSV 规则与安全文案

1. 文件大小、行数、字段长度沿用 core 限制，超限在预览阶段拒绝。
2. BOM 只在输入开头剥离一次，正文中的 BOM 按普通字符处理。
3. 解析器必须支持引号字段内的 CRLF、LF、逗号和双引号。
4. 未闭合引号、引号后非法字符和无效 UTF-8 都是预览错误。
5. 网站导出列固定为 title、url、username、password、totp、notes、tags。
6. 导出不输出 folder、deleted_at、fingerprint、use_count 或审计内容。
7. 空密码但有 TOTP 的行按现有网站迁移规则校验，不擅自补密码。
8. 预览样例用 `has_password`/`has_totp` 布尔值，不回传值本身。
9. 提交结果只记录 inserted、updated、skipped、invalid 的数量。
10. 页面必须显示“CSV 是明文文件，建议导入后立即删除源文件”。
11. 页面必须显示公式注入取舍，并由用户主动确认风险。
12. 操作日志只写格式、数量、结果，不写文件内容和错误行原文。
13. 桌面导出失败保留临时文件名提示，但不自动打开或上传该文件。
14. Android provider 写入中断时提示用户在文件选择器中清理目标。

## 附录 D：同步状态机

1. `idle`：没有预览或提交任务。
2. `reading`：读取本地快照、远端 body 和 ETag。
3. `preview_ready`：内存中持有 token、基线 revision 和逐条动作。
4. `awaiting_choices`：存在冲突，自动同步不得写入。
5. `committing`：重新检查锁、token、revision 和 ETag。
6. `committed`：条件写成功并更新本地快照与墓碑。
7. `stale`：任一本地 revision 或远端 ETag 变化，必须重新预览。
8. `blocked`：provider 无条件写能力、冲突未选择或校验失败。
9. `retryable_error`：网络/超时/条件失败，保留两端数据和用户选择前的内存状态。
10. `locked`：锁定立即清除 token、选择和明文快照。

提交顺序固定为：

1. 检查会话仍解锁。
2. 比对本地 revision 与预览基线。
3. 重新读取并比对远端 ETag。
4. 按逐条选择生成唯一远端对象，执行一次整体条件 PUT；不得先写无冲突项再写冲突项。
5. 网络成功后在本地写事务中提交合并快照，并再次校验本地 revision。
6. 条件写失败或本地事务失败时停止，保留本地、远端及合并快照以便重试恢复。
7. 同步锁覆盖预览、网络写入和本地提交全过程；锁定立即清除冲突快照。

自动同步在任一步发现冲突就停在 `awaiting_choices`，发出通知并记录无秘密的阻塞原因。

## 附录 E：端到端验收案例

1. 从桌面导出含八类条目、证书、独立标签和回收站的 bundle，Android 无库导入后逐字段核对。
2. 输入旧 SBOX1 文件，桌面和 Android 都能预览并导入，且不改变旧文件。
3. 输入截断、改 magic、错误密码和错误 KDF，目标路径均不存在新空库。
4. SAF URI 指向非路径 provider，备份仍能读写且不调用浏览器下载。
5. 证书私钥不匹配时导入失败，UI 不显示私钥内容。
6. CSV 含中文、CRLF、嵌套引号、换行和 BOM，导入再导出后密码字段可往返。
7. CSV 含 `=SUM(1,1)` 密码，确认安全取舍后值不被修改。
8. 修改主密码后旧密码失败、新密码成功、DEK 与 secret 内容不变。
9. 指纹撤销后只能通过主密码解锁，失败不会留下可用 DEK。
10. 删除 folder/tag 后条目仍存在，合并后目标分类和标签关联正确。
11. 手机只编辑标题，expires_at、mailbox 高级字段和 SSH key_type 保持原值。
12. 读取未知 server protocol 后保存，未知值仍可再次读取。
13. 远端同 ETag 被另一设备改写，条件 PUT 失败且本地与远端都保留。
14. 自动同步发现删除对编辑，整次暂停，不自动选择 LWW。
15. 锁定发生在预览到提交之间，选择、token 和待选数据全部清除。
