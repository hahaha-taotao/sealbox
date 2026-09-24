import { createRequire } from "node:module";
import { test } from "node:test";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const fill = require("./fill-logic.cjs");

test("choiceCaptions keeps truncated notes off the primary line", () => {
  assert.deepEqual(
    fill.choiceCaptions([
      { title: "呼市燃热集团供热客服管理系统", username: "xitongguanliyuan", notes: "系统管理员账号，别给外人" },
      { title: "呼市燃热集团供热客服管理系统", username: "chengnan", notes: "城南" },
      { title: "呼市燃热集团供热客服管理系统", username: "jiawang", notes: "   " },
    ]),
    [
      { primary: "xitongguanliyuan", note: "系统管理员账…" },
      { primary: "chengnan", note: "城南" },
      { primary: "jiawang", note: "" },
    ],
  );
  assert.deepEqual(
    fill.choiceCaptions([
      { title: "GitHub", username: "octocat", notes: "工作号" },
      { title: "GitLab", username: "hubot", notes: "机器人账号不要外传" },
    ]),
    [
      { primary: "octocat · GitHub", note: "工作号" },
      { primary: "hubot · GitLab", note: "机器人账号不…" },
    ],
  );
});

test("choiceLabel appends a truncated note after the username", () => {
  assert.equal(
    fill.choiceLabel({
      title: "呼市燃热集团供热客服管理系统",
      username: "18698459937",
      notes: "客服值班账号，别给外人",
      hideTitle: true,
    }),
    "18698459937 · 客服值班账号…",
  );
  assert.equal(
    fill.choiceLabel({
      title: "GitHub",
      username: "octocat",
      notes: "工作号",
    }),
    "octocat · GitHub · 工作号",
  );
  assert.equal(
    fill.choiceLabel({
      title: "GitHub",
      username: "octocat",
      notes: "   ",
    }),
    "octocat · GitHub",
  );
  assert.deepEqual(
    fill.choiceLabels([
      { title: "呼市燃热集团供热客服管理系统", username: "18698459937", notes: "客服值班账号" },
      { title: "呼市燃热集团供热客服管理系统", username: "xitongguanliyuan", notes: "" },
    ]),
    ["18698459937 · 客服值班账号", "xitongguanliyuan"],
  );
});

test("choiceLabel puts the username first and abbreviates a long auto title", () => {
  assert.equal(
    fill.choiceLabel({
      title: "呼市燃热集团供热客服管理系统",
      username: "18698459937",
    }),
    "18698459937 · 呼市燃热…",
  );
  assert.equal(
    fill.choiceLabel({
      title: "呼市燃热集团供热客服管理系统",
      username: "xitongguanliyuan",
    }),
    "xitongguanliyuan · 呼市燃热…",
  );
  assert.equal(
    fill.choiceLabel({
      title: "呼市燃热集团供热客服管理系统",
      username: "18698459937",
      hideTitle: true,
    }),
    "18698459937",
  );
  assert.equal(fill.choiceLabel({ title: "GitHub", username: "octocat" }), "octocat · GitHub");
  assert.equal(fill.choiceLabel({ title: "", username: "" }), "未填账号");
  assert.deepEqual(
    fill.choiceLabels([
      { title: "呼市燃热集团供热客服管理系统", username: "18698459937" },
      { title: "呼市燃热集团供热客服管理系统", username: "xitongguanliyuan" },
    ]),
    ["18698459937", "xitongguanliyuan"],
  );
  assert.deepEqual(
    fill.choiceLabels([
      { title: "GitHub", username: "octocat" },
      { title: "GitLab", username: "hubot" },
    ]),
    ["octocat · GitHub", "hubot · GitLab"],
  );
});

test("sameSite matches scheme, host and port, ignoring www and path", () => {
  assert.equal(fill.sameSite("https://www.github.com/login", "https://github.com/dashboard"), true);
  assert.equal(fill.sameSite("https://github.com:443/login", "https://github.com/"), true);
  assert.equal(fill.sameSite("https://csm.hhughg.com:8280/#", "https://csm.hhughg.com:8280/sof_login.jsp"), true);
  assert.equal(fill.sameSite("https://login.github.com/", "https://github.com/"), false);
  assert.equal(fill.sameSite("https://csm.example.com:8280/", "https://csm.example.com:8281/"), false);
  assert.equal(fill.sameSite("https://csm.example.com:8280/", "http://csm.example.com:8280/"), false);
});

test("isExcluded honors exact hosts and wildcard suffixes", () => {
  const rules = fill.parseExcludeHosts("Example.com\n*.corp.internal\n# comment\n");
  assert.deepEqual(rules, ["example.com", "*.corp.internal"]);
  assert.equal(fill.isExcluded("https://www.example.com/login", rules), true);
  assert.equal(fill.isExcluded("https://app.corp.internal/sso", rules), true);
  assert.equal(fill.isExcluded("https://other.net/", rules), false);
  assert.equal(fill.displayHost("https://www.GitHub.com/login"), "github.com");
  assert.equal(fill.displayHost("https://csm.example.com:8280/x"), "csm.example.com:8280");
  assert.equal(fill.addHostLine("example.com", "https://www.example.com/login"), "example.com");
  assert.equal(fill.addHostLine("", "https://github.com/login"), "github.com");
  assert.equal(fill.addHostLine("a.com", "https://b.com"), "a.com\nb.com");
});

test("classifySave updates same username and otherwise offers a new save", () => {
  const pending = { username: "alice", password: "n3w" };
  assert.equal(fill.classifySave(pending, []).action, "save");
  assert.equal(
    fill.classifySave(pending, [{ id: "1", username: "bob" }]).action,
    "save",
  );
  const update = fill.classifySave(pending, [
    { id: "1", username: "bob" },
    { id: "2", username: "alice" },
  ]);
  assert.equal(update.action, "update");
  assert.equal(update.match.id, "2");
  assert.equal(fill.classifySave({ username: "alice", password: "" }, []).action, "none");
});

test("classifySave skips the prompt when the stored password is unchanged", () => {
  const pending = { username: "alice", password: "same" };
  const matches = [{ id: "2", username: "alice", title: "GitHub" }];
  const unchanged = fill.classifySave(pending, matches, true);
  assert.equal(unchanged.action, "unchanged");
  assert.equal(unchanged.match.id, "2");
  assert.equal(fill.classifySave(pending, matches, false).action, "update");
  assert.equal(fill.classifySave(pending, matches).action, "update");
});

test("overlayDecision prefers save/update after login, else fill on password pages", () => {
  const pending = { action: "update", username: "alice", url: "https://github.com/login" };
  const matches = [{ id: "2", username: "alice" }];
  assert.deepEqual(
    fill.overlayDecision({ pending, matches, hasPassword: false, force: true }),
    { kind: "save", pending },
  );
  assert.deepEqual(
    fill.overlayDecision({ pending, matches, hasPassword: true, force: false }),
    { kind: "save", pending },
  );
  assert.deepEqual(
    fill.overlayDecision({ pending, matches, hasPassword: false, force: false }),
    { kind: "none" },
  );
  assert.deepEqual(
    fill.overlayDecision({
      pending: { action: "unchanged", username: "alice" },
      matches,
      hasPassword: true,
    }),
    { kind: "fill", matches },
  );
  assert.deepEqual(
    fill.overlayDecision({ pending: null, matches, hasPassword: true }),
    { kind: "fill", matches },
  );
  assert.deepEqual(
    fill.overlayDecision({ pending: null, matches, hasPassword: false }),
    { kind: "none" },
  );
});

test("pending save expires after the ttl and skip prompt matches last fill", () => {
  const now = 1_000_000;
  assert.equal(fill.isPendingExpired({ at: now - 60_000 }, now), false);
  assert.equal(fill.isPendingExpired({ at: now - fill.PENDING_TTL_MS - 1 }, now), true);
  assert.equal(
    fill.shouldSkipSavePrompt(
      { username: "a", password: "p", url: "https://github.com/login" },
      { username: "a", password: "p", url: "https://github.com/session", at: now },
      now,
    ),
    true,
  );
  assert.equal(
    fill.shouldSkipSavePrompt(
      { username: "a", password: "p", url: "https://other.net/login" },
      { username: "a", password: "p", url: "https://github.com/login", at: now },
      now,
    ),
    false,
  );
  assert.equal(
    fill.shouldSkipSavePrompt(
      { username: "a", password: "p", url: "https://github.com/login" },
      { username: "a", password: "other", url: "https://github.com/login", at: now },
      now,
    ),
    false,
  );
  assert.equal(
    fill.shouldSkipSavePrompt(
      { username: "a", password: "p", url: "https://github.com/login" },
      { username: "a", password: "p", url: "https://github.com/login", at: now - fill.PENDING_TTL_MS - 1 },
      now,
    ),
    false,
  );
});

test("login action text matches sign-in controls and ignores cancel", () => {
  assert.equal(fill.isLoginActionText("Sign in"), true);
  assert.equal(fill.isLoginActionText("登录"), true);
  assert.equal(fill.isLoginActionText("Cancel"), false);
});

test("pickLoginValues treats a filled text field next to a password as the username", () => {
  const picked = fill.pickLoginValues([
    { type: "search", name: "q", value: "", rendered: true },
    { type: "text", name: "username", value: "18698459937", rendered: true },
    { type: "password", name: "pwd", value: "secret", rendered: true },
  ]);
  assert.equal(picked.username, "18698459937");
  assert.equal(picked.password, "secret");
  const withOtp = fill.pickLoginValues([
    { type: "text", name: "username", value: "alice", rendered: true },
    { type: "password", name: "password", value: "secret", rendered: true },
    { type: "text", autocomplete: "one-time-code", maxlength: "6", value: "123456", rendered: true },
  ]);
  assert.equal(withOtp.username, "alice");
  assert.equal(withOtp.password, "secret");
});

test("pickLoginValues reads a CSS-masked password and still returns the phone number", () => {
  const picked = fill.pickLoginValues([
    { type: "text", name: "phone", value: "18698459937", rendered: true },
    { type: "text", name: "pass", value: "secret", rendered: true, textSecurity: "disc" },
  ]);
  assert.equal(picked.username, "18698459937");
  assert.equal(picked.password, "secret");
  assert.equal(picked.hasPassword, true);
});

test("pickLoginValues keeps a filled username even if no password field is found", () => {
  const picked = fill.pickLoginValues([
    { type: "text", name: "phone", value: "18698459937", rendered: true },
  ]);
  assert.equal(picked.username, "18698459937");
  assert.equal(picked.password, "");
  assert.equal(picked.hasPassword, false);
});

test("nativeValue reads getter-backed fields that hide input.value", () => {
  const proto = {};
  Object.defineProperty(proto, "value", {
    get() {
      return this._v;
    },
    configurable: true,
  });
  const el = Object.create(proto);
  el._v = "18698459937";
  Object.defineProperty(el, "value", { value: "", writable: true, configurable: true });
  assert.equal(fill.nativeValue(el), "18698459937");
});

test("pickLoginValues prefers the visible filled username over a hidden empty email", () => {
  const picked = fill.pickLoginValues([
    { type: "email", name: "email", value: "", hidden: true, rendered: false },
    { type: "text", name: "phone", value: "18698459937", rendered: true },
    { type: "password", name: "password", value: "secret", rendered: true },
  ]);
  assert.equal(picked.username, "18698459937");
  assert.equal(picked.password, "secret");
  assert.equal(picked.hasPassword, true);
  const emptyHidden = fill.pickLoginValues([
    { type: "text", name: "username", value: "", hidden: true, rendered: false },
    { type: "password", value: "p", rendered: true },
  ]);
  assert.equal(emptyHidden.username, "");
  assert.equal(emptyHidden.password, "p");
});

test("pickReadFields prefers the frame that actually has login values", () => {
  assert.deepEqual(fill.pickReadFields([]), { ok: false });
  assert.equal(
    fill.pickReadFields([
      { ok: true, hasPassword: true, username: "", password: "" },
      { ok: true, hasPassword: true, username: "18698459937", password: "secret" },
      { ok: true, hasPassword: false, username: "noise", password: "" },
    ]).username,
    "18698459937",
  );
  assert.equal(
    fill.pickReadFields([
      { ok: true, hasPassword: false, username: "", password: "" },
      { ok: true, hasPassword: true, username: "alice", password: "" },
    ]).username,
    "alice",
  );
  const merged = fill.pickReadFields([
    { ok: true, hasPassword: false, username: "18698459937", password: "" },
    { ok: true, hasPassword: true, username: "", password: "secret" },
  ]);
  assert.equal(merged.username, "18698459937");
  assert.equal(merged.password, "secret");
});

test("fillTokenFromStores prefers session and drops any local leftover", () => {
  assert.deepEqual(fill.fillTokenFromStores({ sessionToken: "s", localToken: "l" }), {
    token: "s",
    writeSession: false,
    removeLocal: true,
  });
  assert.deepEqual(fill.fillTokenFromStores({ sessionToken: "", localToken: "l" }), {
    token: "l",
    writeSession: true,
    removeLocal: true,
  });
  assert.deepEqual(fill.fillTokenFromStores({ sessionToken: "s", localToken: "" }), {
    token: "s",
    writeSession: false,
    removeLocal: false,
  });
  assert.deepEqual(fill.fillTokenFromStores({}), {
    token: "",
    writeSession: false,
    removeLocal: false,
  });
});

test("fillTokenWritePlan never persists the token to local storage", () => {
  assert.deepEqual(fill.fillTokenWritePlan("fill_abc"), {
    token: "fill_abc",
    writeSession: true,
    removeLocal: true,
  });
});

test("background.js never writes fillToken to chrome.storage.local", async () => {
  const { readFile } = await import("node:fs/promises");
  const src = await readFile(new URL("./background.js", import.meta.url), "utf8");
  assert.equal(/storage\.local\.set\(\s*\{[^}]*fillToken/.test(src), false);
  assert.match(src, /storage\.local\.remove\(\s*(?:\[\s*"fillToken"|"fillToken")/);
});

test("isOtpField matches 2FA fields and rejects password or username fields", () => {
  assert.equal(fill.isOtpField({ type: "text", autocomplete: "one-time-code", maxlength: "6" }), true);
  assert.equal(fill.isOtpField({ type: "tel", name: "totp", maxlength: "6" }), true);
  assert.equal(fill.isOtpField({ type: "text", placeholder: "验证码", maxlength: "6" }), true);
  assert.equal(fill.isOtpField({ type: "text", name: "token", maxlength: "8" }), true);
  assert.equal(fill.isOtpField({ type: "text", name: "description", maxlength: "6", value: "hello" }), false);
  assert.equal(fill.isOtpField({ type: "password", name: "otp" }), false);
  assert.equal(fill.isOtpField({ type: "text", name: "password_otp", maxlength: "6" }), false);
  assert.equal(fill.isOtpField({ type: "text", name: "username" }), false);
});

test("pendingTotpPlan expires in at most 30 seconds and validates its code", () => {
  const now = 1_000_000;
  assert.deepEqual(fill.pendingTotpPlan({ totp: "123456", totp_period_remaining: 8 }, now), {
    code: "123456",
    expiresAt: now + 8000,
  });
  assert.equal(fill.pendingTotpPlan({ totp: "123456", totp_period_remaining: 90 }, now).expiresAt, now + 30000);
  assert.equal(fill.pendingTotpPlan({ totp: null }, now), null);
  assert.equal(fill.pendingTotpPlan({ totp: "12345x" }, now), null);
  assert.equal(fill.isPendingTotpExpired({ expiresAt: now - 1 }, now), true);
  assert.equal(fill.isPendingTotpExpired({ expiresAt: now + 1000 }, now), false);
});

test("pickSaveUrl keeps the login-page url when the tab stayed on the same site", () => {
  assert.equal(
    fill.pickSaveUrl("https://github.com/dashboard", "https://github.com/login"),
    "https://github.com/login",
  );
  assert.equal(
    fill.pickSaveUrl("https://evil.example/", "https://github.com/login"),
    "https://evil.example/",
  );
  assert.equal(fill.pickSaveUrl("", "https://github.com/login"), "https://github.com/login");
});
