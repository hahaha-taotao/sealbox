# 页面可见验证码候选识别实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 扩展检测登录页后从当前顶层页面可见文本识别有验证码上下文的 4–8 位数字，向用户展示候选并只在明确确认后填入验证码框。

**Architecture:** 将文本候选识别策略保持为 `fill-logic.cjs` 的纯函数；content script 只在顶层文档遍历可见文本节点，绝不读取表单值、隐藏文本或 iframe；background 验证消息来源、活动标签页 URL 和 TTL，并把候选保留在内存 `Map`；复用已有顶层 shadow overlay 添加独立候选卡片，只有可信用户点击才向 OTP 输入框写入。候选不进入 Tauri、网络请求、日志或 chrome.storage。

**Tech Stack:** Chrome MV3、原生 JavaScript、Node `node:test`、现有 `fill-logic.cjs` / `page-fill.js` / `paintOverlayFunc`。

**Design:** `docs/superpowers/specs/2026-09-28-browser-otp-enrollment-and-page-detection-design.md` §3.2、§4、§5、§6、§7

---

## File map

| File | Responsibility |
|---|---|
| Modify `extension/fill-logic.cjs` | 纯文本候选解析、语义上下文、候选去重、TTL 和优先级决策 |
| Modify `extension/content.js` | 顶层文档可见文本扫描；发送候选到扩展 service worker；保留现有登录字段捕获行为但不复用它读取候选 |
| Modify `extension/background.js` | 校验消息发送者/URL、每 tab 内存候选缓存和清除时机、TOTP/候选优先级、overlay payload、可信确认后填码 |
| Modify `extension/page-fill.js` | 复用字段选择逻辑，只允许写可见/启用/可编辑的 OTP 输入框 |
| Modify `extension/overlay.js` only if popup overlay is also used | 确保用户从 popup/页面两种现有入口看到一致的候选确认动作；优先复用 background 内置 shadow overlay |
| Modify `extension/fill-logic.test.js` | 纯函数识别、候选政策、TTL、歧义和代码中不持久化候选的回归测试 |

## Task 1: 候选提取纯函数

**Files:** `extension/fill-logic.cjs`, `extension/fill-logic.test.js`

- [ ] **Step 1: 添加失败测试**

  测试辅助函数 `otpCandidatesFromText(text)`：有“验证码 / verification code / security code / one-time code / OTP”等上下文的 4、6、8 位数字可识别；3 位、9 位、字母混合串、只有普通文本数字、日期/电话号码附近无语义提示的数字不识别；同一码重复出现时只保留一项；最多返回 5 项；每项只包含 `code` 与长度不超过 80 字符的 `context`；输入文本上限（例如 100,000 字符）之外直接不扫描。

- [ ] **Step 2: 运行测试并确认失败**

  Run: `node --test extension/fill-logic.test.js`
  Expected: 新导出函数不存在导致失败。

- [ ] **Step 3: 实现纯解析和候选排序**

  从有上下文词的窗口中抽取 `\b\d{4,8}\b`，只返回脱敏所需的最小候选对象，不返回整页文本；上下文在数字前后各截取有限字符并移除连续空白。做去重并稳定排序，不替用户预选歧义候选。将上限定义为具名常量并导出用于测试。

- [ ] **Step 4: 验证测试**

  Run: `node --test extension/fill-logic.test.js`
  Expected: 候选识别与拒绝测试全部通过。

- [ ] **Step 5: Commit**

  Commit with `feat(extension): parse contextual page OTP candidates`。

## Task 2: 顶层页面可见文本采集

**Files:** `extension/content.js`, `extension/fill-logic.test.js`

- [ ] **Step 1: 抽出可测试的文本节点筛选规则**

  为 DOM 扫描建立注入式纯函数/小型 DOM helper 测试：仅纳入 `document.body` 内文本节点；跳过 `SCRIPT`、`STYLE`、`NOSCRIPT`、`TEMPLATE`、`INPUT`、`TEXTAREA`、`SELECT`、`OPTION`、`BUTTON`、扩展自身 `#sealbox-overlay-host` 及其后代；必须可见、有布局矩形、祖先无 `display:none` / `visibility:hidden` / `opacity:0`；不读取元素 value、属性值、iframe 文档或 shadow DOM 内容。

- [ ] **Step 2: 添加顶层扫描器**

  在 content script 的候选扫描入口首先要求 `window.top === window.self`；用 TreeWalker 遍历允许的文本节点，合计最多读取 100,000 个字符，之后调用 Task 1 的纯函数。扫描频率复用登录页检测的 debounce/MutationObserver，不额外轮询整页；不得把 `document.documentElement.innerText` 或整页文本传给 background。

- [ ] **Step 3: 只发送最小候选消息**

  找到候选后发送 `{ type: "page-otp-candidates", candidates, url: location.href }`。不发送原始页面文本、输入值、用户名、密码、HTML 或截图。顶层检查只限制新扫描消息，不移除现有兼容多 frame 的密码填充能力。

- [ ] **Step 4: 验证扩展测试与语法**

  Run: `node --check extension/content.js && node --test extension/fill-logic.test.js`
  Expected: 语法和文本候选测试通过；代码中扫描入口有顶层文档约束。

- [ ] **Step 5: Commit**

  Commit with `feat(extension): scan visible OTP context in top page only`。

## Task 3: Background 的内存候选生命周期与消息验证

**Files:** `extension/background.js`, `extension/fill-logic.cjs`, `extension/fill-logic.test.js`

- [ ] **Step 1: 添加失败生命周期测试**

  对新增的纯政策 helper 测试候选 TTL 120 秒；过期、不同 tab、不同 URL、非 top-frame sender、非 HTTP(S) URL、排除站点、锁定/配对失效时不提供候选；consume 后候选只能使用一次；tab 移除和导航离开时移除候选。

- [ ] **Step 2: 添加内存 Map 和校验处理器**

  在 background 中定义 `Map<tabId, { url, candidates, expiresAt }>`。接受消息前检查 `sender.tab.id`、`sender.frameId === 0`、sender URL 与当前 tab URL 同源且一致、页面为 HTTP(S)、站点不在排除列表、候选结构严格满足长度/字符/数量上限。消息的 `msg.url` 只作一致性比较，不作为身份来源。不得持久化到任何 `chrome.storage.*`，不得 console log 候选值/上下文。

- [ ] **Step 3: 实现清理**

  在 `chrome.tabs.onRemoved` 清除对应 Map 和定时器；在 top-frame 主文档 URL 改变、扩展收到已存在的锁定/配对失效响应、排除站点时清除候选。TTL 在 UI 展示前和确认消费前都检查。background service worker 被系统挂起导致候选自然丢失是允许的。

- [ ] **Step 4: 验证候选消息与清理测试**

  Run: `node --check extension/background.js && node --test extension/fill-logic.test.js`
  Expected: 所有非法 sender/URL/TTL 输入都无法产生可消费候选。

- [ ] **Step 5: Commit**

  Commit with `feat(extension): keep page OTP candidates ephemeral`。

## Task 4: 与 TOTP 匹配优先级及页面 overlay 确认

**Files:** `extension/background.js`, `extension/overlay.js` if popup overlay is confirmed active, `extension/fill-logic.cjs`, `extension/fill-logic.test.js`

- [ ] **Step 1: 定义并测试优先级决策**

  明确政策：已有 TOTP 凭据的既有“填充选择”继续由 Rust 生成码并自动填入；页面文本候选绝不覆盖该码。若 TOTP 已配置，仍允许用户显式打开“使用页面可见验证码”折叠选项后手动选择候选；无 TOTP 时有候选才显示候选卡；无候选时现有保存/填充 UI 不变。纯 helper 测试这三类状态。

- [ ] **Step 2: 扩展内置 shadow overlay payload**

  在 `showOverlayOnTab` payload 加候选元数据和最多 5 个候选；新分支允许仅有候选时绘制 overlay，不要求检测到密码框。候选码和 context 使用 `textContent`，禁止 HTML 拼接。每项使用显式“填入此验证码”按钮和“关闭”按钮，不预选，不改变已有凭据 fill 按钮。

- [ ] **Step 3: 仅可信用户确认时填入**

  候选确认 listener 要求 `event.isTrusted`；重新检查 tab、URL、TTL、排除规则，并消费一次候选后才注入。仅顶层 frame 中选可见、启用、非只读 OTP 字段；selector 复用 `Fill.isOtpField` 的等价内联判断，排除 password/hidden；不能找到字段时显示提示并保留到 TTL 到期，不写入其他输入框，也不提交表单。

- [ ] **Step 4: 确认 TOTP 不被候选覆盖**

  测试同屏配置 TOTP 时默认路径仍填 TOTP；页面候选只在用户显式选中后运行，且不会替换 TOTP 自动值。覆盖候选确认前 DOM 无变化、确认后只改 OTP 字段、ignore 不填、重复点击不重复消费。

- [ ] **Step 5: 验证扩展**

  Run: `node --check extension/background.js && node --check extension/overlay.js && node --test extension/fill-logic.test.js`
  Expected: 所有候选优先级和确认门禁测试通过。

- [ ] **Step 6: Commit**

  Commit with `feat(extension): add confirmed page OTP fill overlay`。

## Task 5: 集成回归与文档

**Files:** `README.md`, `extension/fill-logic.test.js`

- [ ] **Step 1: 添加数据边界回归检查**

  用静态源码测试确认候选处理没有调用 `chrome.storage.local/session.set`，没有向 `api()`/`fetchLocal()` 发送候选码，扫描器排除表单元素并只在顶层运行；候选文本只经过 overlay `textContent`。

- [ ] **Step 2: 更新扩展说明**

  说明页面验证码只针对当前页可见文本中的上下文候选，需用户确认后填入；不接短信/邮件服务、不识别 CAPTCHA、不自动提交，也不上传页面内容。

- [ ] **Step 3: 执行全部验证**

  Run: `node --check extension/background.js && node --check extension/content.js && node --check extension/overlay.js && node --test extension/fill-logic.test.js && npm run build && cargo test --manifest-path src-tauri/Cargo.toml --offline && git -c core.whitespace=cr-at-eol diff --check`
  Expected: all commands pass; confirm no new permissions are added.

- [ ] **Step 4: Commit**

  Commit with `test(extension): verify page OTP candidate privacy boundaries`。

## Acceptance criteria

- 自动扫描只读取顶层当前页面可见文本节点，排除表单值、隐藏内容、扩展 overlay 和跨域 iframe。
- 候选必须与中英文验证码语义上下文相关且为 4–8 位数字；多个候选不预选。
- 候选仅在 background 内存保存，最多 120 秒、单 tab/URL 绑定、单次消费；不入 storage、日志、HTTP、审计或 Tauri。
- 用户必须可信点击明确候选操作后才填入顶层 OTP 输入框；不会写到用户名/密码框，不会自动提交。
- 已配置 TOTP 的自动填充继续优先且不被页面候选静默覆盖。
- 不新增浏览器权限，不访问短信、通知、邮件或 CAPTCHA 服务。
