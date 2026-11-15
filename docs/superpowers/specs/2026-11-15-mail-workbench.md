# 邮件工作台与显式服务器管理

## 用户确认范围

- 阅读、收信与附件下载保留；不增加写信、回复、转发、AI。
- 仅增加显式已读/未读切换、单封邮件删除并同步服务器。
- 账号继续在金库内管理，不引入独立账号存储。
- 桌面视觉对齐用户提供的 Sigil 截图：连续三栏、固定正文操作栏、各栏独立滚动、发件人头像、正文工具、附件卡片。
- 手机接入对应管理操作；MCP 保持只读邮箱能力。

本设计更新此前只读规格中“所有入口均禁止服务器写入”的限制；普通读信仍用 EXAMINE/BODY.PEEK，本地自动记已读不隐式写服务器。只有用户主动点已读/未读按钮或确认删除，才进入独立 SELECT/UID STORE 路径。

## 删除语义

当前删除是从服务器永久精确删除，不是移到垃圾箱。界面明确文案并二次确认。仅在服务端宣告 UIDPLUS 后，针对单一 UID 标记 Deleted 并 UID EXPUNGE。没有 UIDPLUS 时在写入前提示，不执行全文件夹 EXPUNGE。若标记成功而移除未确认，显示专门错误，保留当前行以供刷新/重试。

## 一致性

- 本地 seen 与 local_seen 在显式切换成功后统一置为期望值。
- 删除成功写 tombstone，避免旧网络页重新插入该 UID。
- 显式操作递增缓存 revision；已在途的列表和同步结果按 revision 丢弃，避免刚标未读被旧响应改回。
- UI 同时校验账号、文件夹、UID 与页面序号，避免跨账号相同 UID 串扰。
- 网络写失败不提前更新列表；正文错误、附件错误和管理操作错误独立呈现。
- 两端 Tauri invoke 加入 mail_set_seen/mail_delete；MCP 不加入写能力。

## MCP 核查

服务端已有 accounts/folders/list/search/read/save 六个 action，支持 folder/filter/keyword/beforeUid。修补 mailbox 凭据脱敏覆盖、search 凭据类型校验，移除内部遗留别名分支。详见 ../../mail-mcp-audit.md。

当前会话工具注册仍展示旧四 action schema，需重连客户端重新发现后获取新能力；修改源码不会热更新当前会话的已注册工具定义。

## 验证方式

- 两端 vue-tsc 类型检查与 Node 行为回归。
- Core IMAP fixture、缓存与并发 revision 回归。
- 双端 Rust cargo check/test（环境支持的目标）。
- Chromium 独立视觉夹具复用实际 Vue 模板和 CSS，1600×980 / 960×820 截图检查；这不是实际 Tauri IMAP 端到端测试。
- 不生成安装包、不升级版本、不提交或推送。

## 本轮验证结果

- 前端行为回归：64 passed / 0 failed（含手机14项、桌面管理5项）。
- 核心 Rust：214 passed / 0 failed。
- 两端邮件命令/MCP相关测试：桌面7项、移动2项通过。
- 两端 `cargo check --tests` 及 `vue-tsc --noEmit` 通过。
- `scripts/check-version.mjs v0.20.3`：9字段一致，未更改版本。
- 严格 `git diff --check` 通过。
- 视觉夹具检查1600×980下230px/365px/剩余正文三栏，列表与正文独立滚动，无全页横向溢出；960×820下切换式阅读布局。
- 示例截图位于 `docs/prototypes/mail-workbench-desktop.png`、`docs/prototypes/mail-workbench-narrow.png`，使用示例数据；不代表真实邮箱连接验证。
- 未执行真实服务器删除/标记，也未安装桌面或Android端。Windows交叉检查缺 `lib.exe`，改用本机host双端检查与测试通过。
