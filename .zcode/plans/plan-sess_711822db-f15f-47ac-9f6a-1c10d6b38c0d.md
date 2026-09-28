## 目标
把凭据编辑器里的“生成”从固定的 20 位、四类字符全开，升级为可配置的生成器：普通密码支持长度与字符集选择，并可保证每个已选字符类别至少出现一次；新增 passphrase 模式，使用应用内置英文词表生成由分隔符连接的随机词组。现有保存路径和默认生成行为保持兼容。

## 关键约束
- 当前 `src-tauri/src/totp.rs` 只有普通字符抽样，没有 passphrase 或“每类至少一个”能力，因此这两个能力不能只做成前端开关；需要扩展生成器协议，但不改变 `gen_password` 命令名和现有保存模型。
- 工作树已有大量与本需求无关的未提交改动；实现时只触碰生成器相关文件，不回退、不格式化其它改动。
- SSH 的 `passphrase` 字段属于凭据存储模型，本次 passphrase 模式只生成编辑器当前的密码字段，不顺带重构 SSH 表单。
- 口令短语按已确认的“内置英文词表”实现；词数和分隔符由 UI 传入，随机选择只在 Rust 后端完成。

## 实现步骤

1. **扩展后端生成逻辑：`src-tauri/src/totp.rs`**
   - 保留现有普通密码字符集、8–128 长度边界以及没有字符集时的字母数字回退。
   - 将生成逻辑拆成普通密码与 passphrase 两条路径。
   - 普通密码新增 `ensure_each`：先从每个已启用类别各抽取一个字符，再从完整字符池补足长度，最后做 Fisher–Yates 洗牌，保证类别字符不会固定出现在结果开头。
   - 对空字符集和异常长度做后端兜底，避免空池或越界；普通密码实际长度仍由后端 clamp 到 8–128。
   - passphrase 使用内置英文词表（建议独立为 `src-tauri/src/passphrase_words.rs`，避免把词表和算法混在 `totp.rs`）；词数限制为 3–8，默认 4，默认分隔符为 `-`，空分隔符回退到 `-`。输出为随机词连接后的字符串。
   - 在生成器模块增加 Rust 单元测试，覆盖长度 clamp、字符类别限制、`ensure_each` 对每个启用类别的保证、空类别回退、passphrase 词数及分隔符格式。

2. **扩展 Tauri 参数契约：`src-tauri/src/commands.rs`、`src/lib/tauri.ts`**
   - 扩展 `PasswordOpts` 为模式、普通密码选项、`ensure_each`、passphrase 词数和分隔符字段；模式使用明确值 `password` / `passphrase`。
   - 给嵌套参数加显式 serde 命名约定（camelCase 与 TypeScript wrapper 对齐），避免新增字段因 snake_case/camelCase 不一致而静默反序列化失败。
   - 保持 `gen_password` 命令名与 `String` 返回值不变，现有命令注册不需要拆分。
   - 更新 `src/lib/tauri.ts` 的联合类型/参数类型，让 Vue 调用获得编译期检查。

3. **在 `src/App.vue` 增加生成器状态与 UI**
   - 新增独立 reactive 生成器状态：模式、长度/词数、四类字符开关、`ensure_each`、分隔符、选项面板开关和生成中状态。
   - 在 `resetFormFields()`、创建表单和关闭表单时恢复默认生成器设置，避免上一个凭据的设置泄漏到下一个编辑会话；编辑已有凭据时不自动改写现有密码。
   - 将当前密码行（现在是 inline `display:flex` 加固定调用）改为可配置布局：密码输入、生成按钮和设置入口，继续把结果写入 `form.password`，不改变 `buildSecret()`/`saveEntry()`。
   - 普通密码模式显示长度输入（8–128，默认 20）、小写/大写/数字/符号复选框（默认全选）和“每类字符至少一个”（默认开启）。无类别时显示提示，但仍使用后端既有安全回退。
   - passphrase 模式显示词数输入（3–8，默认 4）和分隔符输入（默认 `-`）；隐藏不适用的字符类别与 `ensure_each`，并将标签从“长度”切换为“词数”。
   - `gen()` 使用当前设置调用 `api.genPassword`，生成期间禁用按钮；失败沿用现有 toast 反馈，成功后不额外展示明文。

4. **补充样式：`src/styles.css`**
   - 复用现有 `.secret-row`、`.field`、`.check`、`.btn` 规范，只新增生成器设置容器、紧凑网格和提示文本 class。
   - 为窄窗口提供单列回退，确保编辑对话框内的选项不会挤压密码输入框。

5. **验证**
   - 运行 `npm run build`，验证 Vue 模板、TypeScript API 类型和 Vite 构建。
   - 运行 `cargo test --manifest-path src-tauri/Cargo.toml`，验证新增生成器测试及现有测试。
   - 手工回归默认 20 位全开、改变长度、关闭某类字符、开启/关闭“每类字符至少一个”、切换 passphrase 并验证词数/分隔符、关闭并重新打开表单后默认值恢复，以及生成结果正常保存。

## 预计修改文件
- `src-tauri/src/totp.rs`
- `src-tauri/src/commands.rs`
- `src-tauri/src/lib.rs`（仅在新增词表模块时注册）
- `src-tauri/src/passphrase_words.rs`（新增内置词表）
- `src/lib/tauri.ts`
- `src/App.vue`
- `src/styles.css`

不会修改现有 SSH passphrase 存储协议，也不会纳入工作树中与生成器无关的改动。