try {
  importScripts("fill-logic.cjs");
} catch (e) {
  console.error("Sealbox fill-logic failed to load", e);
}

const Fill = globalThis.SealboxFill || {
  parseExcludeHosts: (text) =>
    String(text || "")
      .split(/\r?\n/)
      .map((line) => line.trim().toLowerCase())
      .filter(Boolean)
      .filter((line) => !line.startsWith("#")),
  originOf: () => null,
  sameSite: () => false,
  isExcluded: () => false,
  isPendingExpired: () => true,
  shouldSkipSavePrompt: () => false,
  classifySave: () => ({ action: "none" }),
  overlayDecision: ({ pending, matches, hasPassword, force } = {}) => {
    const action = pending && pending.action;
    if (pending && action && action !== "none" && action !== "unchanged") {
      if (hasPassword || force) return { kind: "save", pending };
      return { kind: "none" };
    }
    const list = matches || [];
    if (hasPassword && list.length) return { kind: "fill", matches: list };
    return { kind: "none" };
  },
  displayHost: () => "",
  pickSaveUrl: (tabUrl, msgUrl) => tabUrl || msgUrl || "",
  pickReadFields: (replies) =>
    (replies || []).find((r) => r?.hasPassword && (r.username || r.password)) ||
    (replies || []).find((r) => r?.hasPassword) ||
    (replies || []).find((r) => r?.ok) ||
    { ok: false },
  pickLoginValues: () => ({ ok: true, hasPassword: false, username: "", password: "" }),
  abbreviateNote: (notes) => String(notes || "").replace(/\s+/g, " ").trim(),
  choiceLabel: ({ username } = {}) => String(username || "").trim() || "未填账号",
  choiceLabels: (matches) =>
    (matches || []).map((m) => String(m.username || "").trim() || "未填账号"),
  choiceCaptions: (matches) =>
    (matches || []).map((m) => ({
      primary: String(m.username || "").trim() || "未填账号",
      note: String(m.notes || "").replace(/\s+/g, " ").trim(),
    })),
  addHostLine: (text) => text || "",
  fillTokenFromStores: ({ sessionToken, localToken } = {}) => {
    const session = String(sessionToken || "");
    const local = String(localToken || "");
    return {
      token: session || local,
      writeSession: Boolean(!session && local),
      removeLocal: Boolean(local),
    };
  },
  fillTokenWritePlan: (fillToken) => ({
    token: String(fillToken || ""),
    writeSession: true,
    removeLocal: true,
  }),
};
const DEFAULT_PORT = 17891;

async function getPort() {
  const s = await chrome.storage.local.get(["port"]);
  return s.port || DEFAULT_PORT;
}

async function readStoredFillToken(area) {
  try {
    const stored = await chrome.storage[area].get(["fillToken"]);
    return stored.fillToken || "";
  } catch (_) {
    return "";
  }
}

async function applyFillTokenPlan(plan) {
  if (plan.writeSession) {
    try {
      if (plan.token) await chrome.storage.session.set({ fillToken: plan.token });
      else await chrome.storage.session.remove(["fillToken"]);
    } catch (e) {
      if (plan.removeLocal) {
        try {
          await chrome.storage.local.remove(["fillToken"]);
        } catch (_) {
          /* ignore */
        }
      }
      throw e;
    }
  }
  if (plan.removeLocal) {
    try {
      await chrome.storage.local.remove(["fillToken"]);
    } catch (_) {
      /* ignore */
    }
  }
}

async function getFillToken() {
  const plan = Fill.fillTokenFromStores({
    sessionToken: await readStoredFillToken("session"),
    localToken: await readStoredFillToken("local"),
  });
  try {
    await applyFillTokenPlan(plan);
  } catch (_) {
    /* session write failed; still return in-memory token for this worker */
  }
  return plan.token;
}

async function setFillToken(fillToken) {
  await applyFillTokenPlan(Fill.fillTokenWritePlan(fillToken));
}

async function stored() {
  return { port: await getPort(), fillToken: await getFillToken() };
}

function migrateFillTokenToSession() {
  getFillToken().catch(() => {});
}

chrome.runtime.onStartup.addListener(migrateFillTokenToSession);
chrome.runtime.onInstalled.addListener(() => {
  migrateFillTokenToSession();
  chrome.storage.local.remove("showFloatingBar").catch(() => {});
});

async function fetchLocal(path, { body, token, timeoutMs } = {}) {
  const port = await getPort();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs || 8000);
  try {
    const headers = { "Content-Type": "application/json" };
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body || {}),
      signal: ctrl.signal,
    });
    const data = await res.json().catch(() => ({}));
    return { port, res, data };
  } catch (e) {
    if (e?.name === "AbortError") {
      throw new Error("连接 Sealbox 超时。请确认应用已启动，并在「插件」页重新点配对。");
    }
    throw new Error("无法连接 Sealbox，请确认应用已启动");
  } finally {
    clearTimeout(timer);
  }
}

async function pair(code) {
  await sessionRemove(["pendingTotp"]);
  const submitted = String(code || "").trim();
  if (!submitted) throw new Error("请输入一次性配对码");
  const { port, res, data } = await fetchLocal("/fill/pair", { body: { code: submitted } });
  if (!res.ok || !data.fillToken) {
    if (res.status === 403 && /locked/i.test(String(data.error || ""))) {
      throw new Error("金库已锁定，请先解锁 Sealbox");
    }
    if (/pairing window/i.test(String(data.error || ""))) {
      throw new Error("配对窗口未开放或已过期，请在 Sealbox 点「配对浏览器插件」");
    }
    if (/invalid pairing code/i.test(String(data.error || ""))) {
      throw new Error("配对码不正确");
    }
    throw new Error(data.error || "无法连接 Sealbox，请确认应用已启动");
  }
  await setFillToken(data.fillToken);
  await chrome.storage.local.set({ port: data.port || port });
  return { ok: true, port: data.port || port };
}

async function api(path, body) {
  const { fillToken } = await stored();
  if (!fillToken) {
    throw new Error("尚未配对。请在 Sealbox 点「配对浏览器插件」，再把一次性配对码填进扩展。");
  }
  const { res, data } = await fetchLocal(path, { body, token: fillToken });
  if (res.status === 401) {
    await sessionRemove(["pendingTotp"]);
    throw new Error("填表 Token 已失效，请重新配对");
  }
  if (!res.ok || data.ok === false) {
    if (res.status === 403 && data.error === "vault locked") {
      await sessionRemove(["pendingTotp"]);
      throw new Error("金库已锁定，请先解锁 Sealbox");
    }
    if (res.status === 403) throw new Error(data.error || "拒绝访问");
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

async function getSettings() {
  const s = await chrome.storage.local.get(["excludeText"]);
  const excludeText = String(s.excludeText || "");
  return {
    excludeText,
    excludeHosts: Fill.parseExcludeHosts(excludeText),
  };
}

async function sessionGet(keys) {
  try {
    return await chrome.storage.session.get(keys);
  } catch (_) {
    return {};
  }
}

async function sessionSet(obj) {
  await chrome.storage.session.set(obj);
}

async function sessionRemove(keys) {
  try {
    await chrome.storage.session.remove(keys);
  } catch (_) {
    /* session storage unavailable */
  }
}

async function getPending() {
  const s = await sessionGet(["pendingSave"]);
  const pending = s.pendingSave;
  if (!pending || Fill.isPendingExpired(pending, Date.now())) {
    if (pending) await sessionRemove(["pendingSave"]);
    return null;
  }
  return pending;
}

async function rememberFill(entry, pageUrl) {
  if (!entry) return;
  const pendingTotp = Fill.pendingTotpPlan?.(entry);
  const cfg = pendingTotp ? await getSettings() : null;
  if (pendingTotp && Fill.originOf?.(pageUrl) && !Fill.isExcluded(pageUrl, cfg.excludeHosts)) {
    await sessionSet({ pendingTotp: { ...pendingTotp, url: pageUrl, username: entry.username || "" } });
  } else {
    await sessionRemove(["pendingTotp"]);
  }
  await sessionSet({
    lastFilled: {
      username: entry.username || "",
      password: entry.password || "",
      url: pageUrl || "",
      at: Date.now(),
    },
  });
}

async function captureLogin(pendingSave, pageUrl, tabId) {
  const password = String(pendingSave?.password || "");
  if (!password) return { ok: true };
  const pending = {
    url: pageUrl || String(pendingSave.url || ""),
    title: String(pendingSave.title || ""),
    username: String(pendingSave.username || ""),
    password,
    tabId: tabId || 0,
    at: Number(pendingSave.at) || Date.now(),
  };
  if (!Fill.originOf(pending.url)) return { ok: true };
  const cfg = await getSettings();
  if (Fill.isExcluded(pending.url, cfg.excludeHosts)) return { ok: true, skipped: true };
  const filled = (await sessionGet(["lastFilled"])).lastFilled;
  if (Fill.shouldSkipSavePrompt(pending, filled)) {
    await sessionRemove(["pendingSave"]);
    return { ok: true, skipped: true };
  }
  await sessionSet({ pendingSave: pending });
  return { ok: true, captured: true };
}

async function skipPendingIfFilled(pending) {
  if (!pending) return null;
  const filled = (await sessionGet(["lastFilled"])).lastFilled;
  if (Fill.shouldSkipSavePrompt(pending, filled)) {
    await sessionRemove(["pendingSave"]);
    return null;
  }
  return pending;
}

function senderPageUrl(sender, msgUrl) {
  const tabUrl = sender.tab?.url || "";
  const frameUrl = sender.url || "";
  const page = /^https?:/i.test(tabUrl) ? tabUrl : /^https?:/i.test(frameUrl) ? frameUrl : "";
  return Fill.pickSaveUrl(page, msgUrl || "");
}

async function describePending(pageUrl, tabId) {
  let pending = await skipPendingIfFilled(await getPending());
  if (!pending) return { ok: true, pending: null };
  const sameTab = tabId && pending.tabId && Number(tabId) === Number(pending.tabId);
  if (pageUrl && !Fill.sameSite(pageUrl, pending.url) && !sameTab) return { ok: true, pending: null };
  const cfg = await getSettings();
  if (Fill.isExcluded(pending.url, cfg.excludeHosts)) {
    await sessionRemove(["pendingSave"]);
    return { ok: true, pending: null };
  }
  const publicPending = (action) => ({
    title: pending.title,
    url: pending.url,
    username: pending.username,
    host: Fill.displayHost(pending.url) || pending.title || "",
    action,
  });
  if (pending.action === "save" || pending.action === "update") {
    return { ok: true, pending: publicPending(pending.action) };
  }
  if (pending.action === "none" || pending.action === "unchanged") {
    await sessionRemove(["pendingSave"]);
    return { ok: true, pending: null };
  }
  let classification = { action: "save" };
  try {
    const c = await api("/fill/classify", {
      url: pending.url,
      username: pending.username,
      password: pending.password,
    });
    const action = String(c.action || "");
    classification = {
      action: action || "save",
      match: c.id ? { id: c.id } : null,
    };
  } catch (_) {
    let matches = [];
    try {
      const m = await api("/fill/match", { url: pending.url });
      matches = m.matches || [];
    } catch (__) {
      matches = [];
    }
    classification = Fill.classifySave(pending, matches);
  }
  if (classification.action === "none" || classification.action === "unchanged") {
    await sessionRemove(["pendingSave"]);
    return { ok: true, pending: null };
  }
  await sessionSet({ pendingSave: { ...pending, action: classification.action } });
  return {
    ok: true,
    pending: publicPending(classification.action),
  };
}

async function confirmSave(pageUrl, fromContentScript, tabId) {
  const pending = await getPending();
  if (!pending) throw new Error("没有待保存的登录");
  if (fromContentScript) {
    const sameSite = pageUrl && Fill.sameSite(pageUrl, pending.url);
    const sameTab = tabId && pending.tabId && Number(tabId) === Number(pending.tabId);
    if (!sameSite && !sameTab) throw new Error("当前页面与待保存站点不一致");
  }
  const data = await api("/fill/save", {
    title: pending.title,
    url: pending.url,
    username: pending.username,
    password: pending.password,
  });
  await rememberFill(
    { username: pending.username, password: pending.password },
    pending.url,
  );
  await sessionRemove(["pendingSave"]);
  return data;
}

async function excludeSite(url) {
  const cfg = await getSettings();
  const excludeText = Fill.addHostLine(cfg.excludeText, url);
  await chrome.storage.local.set({ excludeText });
  const pending = await getPending();
  if (pending && Fill.sameSite(pending.url, url)) await sessionRemove(["pendingSave"]);
  const pendingTotp = (await sessionGet(["pendingTotp"])).pendingTotp;
  if (pendingTotp && Fill.sameSite(pendingTotp.url, url)) await sessionRemove(["pendingTotp"]);
  return getSettings();
}

async function injectFrame(tabId, frameId) {
  const target = frameId == null ? { tabId } : { tabId, frameIds: [frameId] };
  try {
    await chrome.scripting.executeScript({
      target,
      files: ["fill-logic.cjs", "page-fill.js", "content.js"],
    });
    return true;
  } catch (_) {
    return false;
  }
}

async function listFrames(tabId) {
  try {
    const frames = await chrome.webNavigation.getAllFrames({ tabId });
    if (Array.isArray(frames) && frames.length) return frames;
  } catch (_) {
    /* webNavigation unavailable */
  }
  return [{ frameId: 0, url: (await chrome.tabs.get(tabId)).url }];
}

async function listFrameIds(tabId) {
  return (await listFrames(tabId)).map((frame) => frame.frameId);
}

async function injectTab(tabId) {
  if (!tabId) return false;
  const ids = await listFrameIds(tabId);
  const results = await Promise.all(ids.map((frameId) => injectFrame(tabId, frameId)));
  if (results.some(Boolean)) return true;
  return injectFrame(tabId);
}

async function pingFrames(tabId, message) {
  const ids = await listFrameIds(tabId);
  const replies = [];
  for (const frameId of ids) {
    try {
      replies.push(await chrome.tabs.sendMessage(tabId, message, { frameId }));
    } catch (_) {
      /* no listener in this frame */
    }
  }
  return replies;
}

function fillFunc(username, password, totp) {
  const collect = (root, acc) => {
    if (!root) return acc;
    for (const el of root.querySelectorAll("input, textarea")) acc.push(el);
    for (const el of root.querySelectorAll("*")) {
      if (el.shadowRoot) collect(el.shadowRoot, acc);
    }
    return acc;
  };
  const inputs = collect(document, []);
  const isPwd = (el) => {
    const type = String(el.type || "").toLowerCase();
    const a = `${type} ${el.name || ""} ${el.id || ""} ${el.placeholder || ""} ${el.autocomplete || ""}`;
    return type === "password" || /password|passwd|pwd|secret|密码|口令/i.test(a);
  };
  const passwordEl = inputs.find(isPwd);
  if (!passwordEl) return { ok: false, error: "no-password-field", count: inputs.length };
  const isOtp = (el) => {
    const type = String(el.type || "").toLowerCase();
    const labelText = el.labels ? Array.from(el.labels).map((label) => label.textContent || "").join(" ") : el.closest("label")?.textContent || "";
      const text = `${el.name || ""} ${el.id || ""} ${el.placeholder || ""} ${el.getAttribute("aria-label") || ""} ${labelText} ${el.className || ""} ${el.autocomplete || ""}`;
      if (type === "password" || type === "hidden" || /password|passwd|pwd|secret|密码|口令/i.test(text)) return false;
      if (String(el.autocomplete || "").toLowerCase().trim() === "one-time-code") return true;
      const max = Number(el.getAttribute("maxlength") || el.maxLength || 0);
      const numericOnly = /^\d*$/.test(String(el.value || ""));
      return /otp|totp|2fa|mfa|one[-_ ]?time|verification|验证码|动态码|校验码|安全码/i.test(text) && (!max || max === 6 || max === 8) ||
        (["text", "number", "tel", ""].includes(type) && (max === 6 || max === 8) && numericOnly);
  };
  const otpEl = totp ? inputs.find((el) => isOtp(el) && !el.disabled && !el.readOnly && el.getClientRects().length) : null;
  const userEl =
    inputs.find((el) => el !== passwordEl && el !== otpEl && String(el.type || "").toLowerCase() === "email") ||
    inputs.find((el) => el !== passwordEl && el !== otpEl && /user|login|email|account|phone|mobile|账号|用户|工号/i.test(`${el.name} ${el.id} ${el.placeholder}`)) ||
    inputs.find((el) => el !== passwordEl && el !== otpEl && ["text", "tel", "number", ""].includes(String(el.type || "").toLowerCase()));
  const set = (el, value) => {
    if (!el) return;
    const wasReadOnly = el.readOnly;
    const wasDisabled = el.disabled;
    el.readOnly = false;
    el.disabled = false;
    el.focus();
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
    setter ? setter.call(el, value) : (el.value = value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    el.readOnly = wasReadOnly;
    el.disabled = wasDisabled;
  };
  set(userEl, username || "");
  set(passwordEl, password || "");
  if (otpEl) set(otpEl, totp);
  return { ok: true, filledTotp: Boolean(otpEl) };
}

async function executeFill(tabId, frameId, entry, world) {
  const target = frameId == null ? { tabId } : { tabId, frameIds: [frameId] };
  try {
    const results = await chrome.scripting.executeScript({
      target,
      world,
      func: fillFunc,
      args: [entry.username || "", entry.password || "", entry.totp || ""],
    });
    return results?.find((r) => r?.result?.ok)?.result || { ok: false };
  } catch (_) {
    return false;
  }
}

async function applyPendingTotpIfNeeded(tab) {
  if (!tab?.id || !/^https?:/i.test(tab.url || "")) return false;
  const pending = (await sessionGet(["pendingTotp"])).pendingTotp;
  if (!pending) return false;
  if (Fill.isPendingTotpExpired?.(pending, Date.now()) || !Fill.sameSite?.(pending.url, tab.url)) {
    await sessionRemove(["pendingTotp"]);
    return false;
  }
  const cfg = await getSettings();
  if (Fill.isExcluded(pending.url, cfg.excludeHosts) || Fill.isExcluded(tab.url, cfg.excludeHosts)) {
    await sessionRemove(["pendingTotp"]);
    return false;
  }
  const otpFunc = (code) => {
    const collect = (root, acc) => {
      if (!root) return acc;
      try {
        for (const el of root.querySelectorAll("input, textarea")) acc.push(el);
        for (const el of root.querySelectorAll("*")) if (el.shadowRoot) collect(el.shadowRoot, acc);
      } catch (_) { /* closed shadow */ }
      return acc;
    };
    const isOtp = (el) => {
      const type = String(el.type || "").toLowerCase();
      const labelText = el.labels ? Array.from(el.labels).map((label) => label.textContent || "").join(" ") : el.closest("label")?.textContent || "";
      const text = `${el.name || ""} ${el.id || ""} ${el.placeholder || ""} ${el.getAttribute("aria-label") || ""} ${labelText} ${el.className || ""} ${el.autocomplete || ""}`;
      if (type === "password" || type === "hidden" || /password|passwd|pwd|secret|密码|口令/i.test(text)) return false;
      if (String(el.autocomplete || "").toLowerCase().trim() === "one-time-code") return true;
      const max = Number(el.getAttribute("maxlength") || el.maxLength || 0);
      const numericOnly = /^\\d*$/.test(String(el.value || ""));
      return /otp|totp|2fa|mfa|one[-_ ]?time|verification|验证码|动态码|校验码|安全码/i.test(text) && (!max || max === 6 || max === 8) ||
        (["text", "number", "tel", ""].includes(type) && (max === 6 || max === 8) && numericOnly);
    };
    const el = collect(document, []).find((item) => isOtp(item) && !item.disabled && !item.readOnly && item.getClientRects().length);
    if (!el) return { ok: false };
    el.focus();
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    setter ? setter.call(el, code) : (el.value = code);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return { ok: true };
  };
  const frame = (await listFrames(tab.id)).find((item) => item.frameId === 0);
  if (!frame || !Fill.sameSite(pending.url, frame.url || "")) return false;
  try {
    const results = await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds: [0] }, world: "ISOLATED", func: otpFunc, args: [pending.code] });
    if (results?.some((r) => r?.result?.ok)) {
      await sessionRemove(["pendingTotp"]);
      return true;
    }
  } catch (_) { /* frame unavailable */ }
  return false;
}

async function applySecretToTab(tabId, entry, pageUrl) {
  const frames = await listFrames(tabId);
  for (const world of ["ISOLATED", "MAIN"]) {
    for (const frame of frames) {
      const frameEntry = {
        ...entry,
        totp: Fill.sameSite(pageUrl, frame.url || "") ? entry.totp || "" : "",
      };
      const result = await executeFill(tabId, frame.frameId, frameEntry, world);
      if (result?.ok) {
        if (result.filledTotp) await sessionRemove(["pendingTotp"]);
        return { ok: true };
      }
    }
  }
  await injectTab(tabId);
  const replies = await pingFrames(tabId, {
    type: "apply-secret",
    username: entry.username,
    password: entry.password,
    totp: "",
  });
  if (replies.some((reply) => reply?.ok)) return { ok: true };
  return { ok: false, error: "页面上没有密码框，或当前页无法注入脚本。请刷新登录页后再点填充。" };
}

function readFieldsFunc() {
  const nativeValue = (el) => {
    if (!el) return "";
    let proto = Object.getPrototypeOf(el);
    while (proto && proto !== Object.prototype) {
      const desc = Object.getOwnPropertyDescriptor(proto, "value");
      if (desc?.get) {
        try {
          const v = desc.get.call(el);
          if (v != null && String(v) !== "") return String(v);
        } catch (_) {
          /* ignore */
        }
      }
      proto = Object.getPrototypeOf(proto);
    }
    if (el.value != null && String(el.value) !== "") return String(el.value);
    const text = el.textContent || el.innerText || "";
    return String(text || "").trim();
  };
  const collect = (root, acc) => {
    if (!root) return acc;
    try {
      for (const el of root.querySelectorAll("input, textarea, [contenteditable=true]")) acc.push(el);
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) collect(el.shadowRoot, acc);
      }
    } catch (_) {
      /* closed shadow */
    }
    return acc;
  };
  const snapshot = (el) => {
    let rendered = false;
    let hidden = String(el.type || "").toLowerCase() === "hidden";
    let textSecurity = "";
    try {
      const st = getComputedStyle(el);
      const r = el.getBoundingClientRect();
      rendered = r.width > 0 && r.height > 0;
      hidden =
        hidden ||
        st.display === "none" ||
        st.visibility === "hidden" ||
        Number(st.opacity) === 0;
      textSecurity = st.webkitTextSecurity || st.textSecurity || "";
    } catch (_) {
      /* detached */
    }
    const tag = String(el.tagName || "").toLowerCase();
    return {
      type: el.type || (el.isContentEditable ? "text" : tag),
      name: el.name || "",
      id: el.id || "",
      placeholder: el.placeholder || "",
      autocomplete: el.autocomplete || "",
      className: String(el.className || ""),
      ariaLabel: el.getAttribute?.("aria-label") || "",
      value: nativeValue(el),
      hidden,
      rendered,
      disabled: Boolean(el.disabled),
      readOnly: Boolean(el.readOnly),
      textSecurity,
    };
  };
  const fields = collect(document, []).map(snapshot);
  const isPwd = (f) => {
    const type = String(f.type || "").toLowerCase();
    const a = `${type} ${f.name || ""} ${f.id || ""} ${f.placeholder || ""} ${f.autocomplete || ""} ${f.className || ""}`;
    return type === "password" || /disc|circle|square/i.test(String(f.textSecurity || "")) || /password|passwd|pwd|secret|密码|口令/i.test(a);
  };
  const pwdScore = (f) => {
    if (!isPwd(f)) return -1;
    let n = 10;
    if (String(f.type || "").toLowerCase() === "password") n += 20;
    if (/disc|circle|square/i.test(String(f.textSecurity || ""))) n += 25;
    if (String(f.value || "")) n += 100;
    if (f.rendered) n += 20;
    if (f.hidden || f.disabled) n -= 40;
    return n;
  };
  const userScore = (f) => {
    if (isPwd(f)) return -1;
    const type = String(f.type || "").toLowerCase();
    if (["hidden", "submit", "button", "checkbox", "radio", "file", "image", "reset"].includes(type)) return -1;
    const value = String(f.value || "").trim();
    if (f.hidden && !value) return -1;
    let n = 0;
    if (value) n += 100;
    if (f.rendered) n += 20;
    else n -= 10;
    if (f.hidden) n -= 50;
    if (type === "email" || type === "tel") n += 15;
    const a = `${f.name || ""} ${f.id || ""} ${f.placeholder || ""} ${f.autocomplete || ""} ${f.className || ""} ${f.ariaLabel || ""}`;
    if (/user|login|email|account|phone|mobile|账号|用户|工号|手机/i.test(a)) n += 30;
    if (/^1\d{10}$/.test(value) || /@/.test(value)) n += 20;
    if (type === "text" || type === "number" || type === "search" || type === "tel" || !type) n += 5;
    return n;
  };
  let passwordIndex = -1;
  let bestPwd = -1;
  let usernameIndex = -1;
  let bestUser = -1;
  for (let i = 0; i < fields.length; i += 1) {
    const p = pwdScore(fields[i]);
    if (p > bestPwd) {
      bestPwd = p;
      passwordIndex = i;
    }
  }
  for (let i = 0; i < fields.length; i += 1) {
    if (i === passwordIndex) continue;
    const u = userScore(fields[i]);
    if (u > bestUser) {
      bestUser = u;
      usernameIndex = i;
    }
  }
  return {
    ok: true,
    hasPassword: bestPwd >= 0,
    username: usernameIndex >= 0 ? String(fields[usernameIndex].value || "") : "",
    password: passwordIndex >= 0 ? String(fields[passwordIndex].value || "") : "",
    fieldCount: fields.length,
  };
}

function normalizeReadReply(reply) {
  if (!reply) return null;
  if (Array.isArray(reply.fields)) {
    return Fill.pickLoginValues ? Fill.pickLoginValues(reply.fields) : reply;
  }
  return {
    ok: Boolean(reply.ok),
    username: String(reply.username || ""),
    password: String(reply.password || ""),
    hasPassword: Boolean(reply.hasPassword || reply.password),
  };
}

async function executeRead(tabId, frameId, world) {
  const target = frameId == null ? { tabId } : { tabId, frameIds: [frameId] };
  try {
    const results = await chrome.scripting.executeScript({
      target,
      world,
      func: readFieldsFunc,
    });
    return (results || []).map((r) => normalizeReadReply(r?.result)).filter(Boolean);
  } catch (_) {
    return [];
  }
}

async function readFieldsFromTab(tabId) {
  const replies = [];
  for (const world of ["MAIN", "ISOLATED"]) {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId, allFrames: true },
        world,
        func: readFieldsFunc,
      });
      replies.push(...(results || []).map((r) => normalizeReadReply(r?.result)).filter(Boolean));
    } catch (_) {
      const ids = await listFrameIds(tabId);
      for (const frameId of ids) replies.push(...(await executeRead(tabId, frameId, world)));
    }
    const picked = Fill.pickReadFields(replies);
    if (picked?.username || picked?.password) return picked;
  }
  return Fill.pickReadFields(replies);
}

function removeOverlayFunc() {
  document.getElementById("sealbox-overlay-host")?.remove();
  document.getElementById("sealbox-overlay-frame")?.remove();
  return { ok: true };
}

async function runOnTopFrame(tabId, func, args) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      world: "ISOLATED",
      func,
      args: args || [],
    });
    return results?.[0]?.result || { ok: true };
  } catch (e) {
    return { ok: false, error: String(e.message || e) };
  }
}

function paintOverlayFunc(payload) {
  const HOST_ID = "sealbox-overlay-host";
  const data = Array.isArray(payload) ? { kind: "fill", matches: payload } : payload || {};
  const kind = data.kind || "fill";
  const force = Boolean(data.force);
  const pending = data.pending || null;
  const collect = (root, acc) => {
    if (!root) return acc;
    try {
      for (const el of root.querySelectorAll("input, textarea")) acc.push(el);
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) collect(el.shadowRoot, acc);
      }
    } catch (_) {
      /* closed shadow */
    }
    return acc;
  };
  const inputs = collect(document, []);
  const hasPassword = inputs.some((el) => {
    const type = String(el.type || "").toLowerCase();
    const a = `${type} ${el.name || ""} ${el.id || ""} ${el.placeholder || ""} ${el.autocomplete || ""}`;
    return type === "password" || /password|passwd|pwd|secret|密码|口令/i.test(a);
  });
  const href = String(location.href || "");
  const canSave = kind === "save" && pending && (hasPassword || force);
  const list = Array.isArray(data.matches) ? data.matches : [];
  if (!canSave && !hasPassword) {
    document.getElementById(HOST_ID)?.remove();
    return { painted: false, hasPassword: false, href };
  }
  if (!canSave && !list.length) {
    document.getElementById(HOST_ID)?.remove();
    return { painted: false, hasPassword: true, href, reason: "no-matches" };
  }

  const sig = [
    canSave ? "save" : "fill",
    pending?.action || "",
    pending?.username || "",
    pending?.url || "",
    list.map((m) => m.id).join(","),
  ].join("|");
  const existing = document.getElementById(HOST_ID);
  if (existing?.dataset?.sealboxSig === sig) {
    return { painted: true, hasPassword, href, kind: canSave ? "save" : "fill", reused: true };
  }

  const maskAccount = (username) => {
    const s = String(username || "").trim();
    if (!s) return "未填账号";
    if (s.length <= 2) return `${s[0] || ""}*`;
    return `${s.slice(0, 2)}···${s.slice(-1)}`;
  };
  const shortNote = (notes) => {
    const text = String(notes || "").replace(/\s+/g, " ").trim();
    if (!text) return "";
    const chars = [...text];
    return chars.length <= 8 ? text : `${chars.slice(0, 6).join("")}…`;
  };
  const captions = (list || []).map((m) => {
    const note = m.note || shortNote(m.notes);
    const badge = m.has_totp || m.badge ? "验证码" : "";
    if (m.primary) return { primary: m.primary, note, badge };
    const user = String(m.username || "").trim() || "未填账号";
    return { primary: m.label || user, note, badge };
  });
  const send = (message, done) => {
    const runtime = globalThis.chrome?.runtime;
    if (runtime?.sendMessage) {
      runtime.sendMessage(message, done);
      return;
    }
    if (message.type === "fill-tab") {
      window.postMessage({ source: "sealbox-overlay", type: "fill-tab", id: message.id }, "*");
    }
  };

  document.getElementById(HOST_ID)?.remove();
  const host = document.createElement("div");
  host.id = HOST_ID;
  host.dataset.sealboxSig = sig;
  host.style.cssText = [
    "all:initial",
    "position:fixed",
    "z-index:2147483647",
    "right:16px",
    "bottom:16px",
    "width:240px",
    "display:block",
    "pointer-events:auto",
  ].join(";");
  const root = host.attachShadow({ mode: "open" });
  const wrap = document.createElement("div");
  wrap.style.cssText =
    "background:#1f2329;color:#fff;padding:10px 12px;border-radius:10px;font:13px/1.4 Segoe UI,sans-serif;box-shadow:0 8px 24px rgba(0,0,0,.25);";
  const title = document.createElement("div");
  title.style.marginBottom = "6px";
  wrap.appendChild(title);
  const fail = (res, fallback) => {
    title.textContent = res?.error || fallback;
    title.style.color = "#fca5a5";
  };
  const btnStyle =
    "display:block;width:100%;margin:4px 0;padding:6px 8px;border:0;border-radius:6px;background:#5b5bd6;color:#fff;cursor:pointer;font:inherit;text-align:left;overflow:hidden;";
  const lineStyle =
    "display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;";
  const ghostStyle = "margin-top:4px;margin-right:8px;border:0;background:transparent;color:#aaa;cursor:pointer;font:inherit;";

  if (canSave) {
    const isUpdate = pending.action === "update";
    title.textContent = isUpdate ? "Sealbox · 更新此密码？" : "Sealbox · 保存此密码？";
    const meta = document.createElement("div");
    meta.textContent = `${pending.host || pending.title || "当前站点"} · ${maskAccount(pending.username)}`;
    meta.style.cssText = "color:#c9cdd4;margin-bottom:8px;";
    wrap.appendChild(meta);
    const ok = document.createElement("button");
    ok.type = "button";
    ok.textContent = isUpdate ? "更新到金库" : "保存到金库";
    ok.style.cssText = btnStyle;
    ok.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      send({ type: "confirm-save" }, (res) => {
        if (res?.ok) host.remove();
        else fail(res, "保存失败");
      });
    });
    wrap.appendChild(ok);
    const never = document.createElement("button");
    never.type = "button";
    never.textContent = "不再询问此站点";
    never.style.cssText = ghostStyle;
    never.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      send({ type: "exclude-site", url: pending.url }, () => host.remove());
    });
    wrap.appendChild(never);
    const skip = document.createElement("button");
    skip.type = "button";
    skip.textContent = "不保存";
    skip.style.cssText = ghostStyle;
    skip.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      send({ type: "clear-pending" }, () => host.remove());
    });
    wrap.appendChild(skip);
  } else {
    title.textContent = list.length > 1 ? `Sealbox · ${list.length} 个匹配` : "Sealbox · 填充";
    list.slice(0, 8).forEach((m, i) => {
      const b = document.createElement("button");
      b.type = "button";
      const caption = captions[i] || { primary: String(m.username || "").trim() || "未填账号", note: "" };
      const primaryEl = document.createElement("span");
      primaryEl.textContent = caption.primary;
      primaryEl.style.cssText = lineStyle;
      b.appendChild(primaryEl);
      if (caption.note) {
        const noteEl = document.createElement("span");
        noteEl.textContent = caption.note;
        noteEl.style.cssText = `${lineStyle}margin-top:2px;font-size:11px;line-height:1.3;color:rgba(255,255,255,.72);`;
        b.appendChild(noteEl);
      }
      if (caption.badge) {
        const badgeEl = document.createElement("span");
        badgeEl.textContent = "验证码";
        badgeEl.style.cssText = "display:inline-block;margin-top:3px;font-size:10px;line-height:1.2;color:rgba(255,255,255,.55);";
        b.appendChild(badgeEl);
      }
      b.style.cssText = btnStyle;
      b.addEventListener("click", (e) => {
        if (!e.isTrusted) return;
        send({ type: "fill-tab", id: m.id }, (res) => {
          if (res?.ok) host.remove();
          else fail(res, "填充失败");
        });
      });
      wrap.appendChild(b);
    });
    const close = document.createElement("button");
    close.type = "button";
    close.textContent = "关闭";
    close.style.cssText = ghostStyle;
    close.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      host.remove();
    });
    wrap.appendChild(close);
  }
  root.appendChild(wrap);
  (document.documentElement || document.body).appendChild(host);
  return { painted: true, hasPassword, href, kind: canSave ? "save" : "fill" };
}

async function injectOverlay(tabId, payload) {
  const ids = await listFrameIds(tabId);
  const reports = [];
  let lastErr = "";
  const run = async (frameId, data) => {
    const results = await chrome.scripting.executeScript({
      target: { tabId, frameIds: [frameId] },
      world: "ISOLATED",
      func: paintOverlayFunc,
      args: [data],
    });
    return results?.map((r) => r?.result).filter(Boolean) || [];
  };
  for (const frameId of ids) {
    try {
      reports.push(...(await run(frameId, payload)));
    } catch (e) {
      lastErr = String(e.message || e);
    }
  }
  if (!reports.some((r) => r.painted)) {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId, allFrames: true },
        world: "ISOLATED",
        func: paintOverlayFunc,
        args: [payload],
      });
      reports.push(...(results || []).map((r) => r?.result).filter(Boolean));
    } catch (e) {
      lastErr = lastErr || String(e.message || e);
    }
  }
  const painted = reports.filter((r) => r.painted);
  if (painted.length) return { ok: true, painted: true, frames: painted.length, kind: payload.kind };
  if (payload.kind === "save") {
    try {
      const forced = await run(0, { ...payload, force: true });
      if (forced.some((r) => r.painted)) return { ok: true, painted: true, frames: 1, kind: "save" };
    } catch (e) {
      lastErr = lastErr || String(e.message || e);
    }
    return { ok: false, painted: false, error: lastErr || "登录后未能弹出保存/更新卡片" };
  }
  const passwordFrames = reports.filter((r) => r.hasPassword);
  if (lastErr && !reports.length) return { ok: false, painted: false, error: lastErr };
  if (!passwordFrames.length) {
    return { ok: false, painted: false, error: "已匹配账号，但当前可见页面里还没找到密码框。请点到登录框后再打开插件。" };
  }
  return { ok: false, painted: false, error: lastErr || "找到了密码框，但卡片没能画出来" };
}

async function matchesForTab(tab) {
  if (!tab?.url || !/^https?:/i.test(tab.url)) return [];
  const cfg = await getSettings();
  if (Fill.isExcluded(tab.url, cfg.excludeHosts)) return [];
  const data = await api("/fill/match", { url: tab.url });
  return data.matches || [];
}

async function showOverlayOnTab(tab) {
  if (!tab?.id || !/^https?:/i.test(tab.url || "")) return { ok: false };
  await applyPendingTotpIfNeeded(tab).catch(() => false);
  const pendingRes = await describePending(tab.url, tab.id).catch(() => ({ pending: null }));
  const pending = pendingRes?.pending || null;
  let matches = [];
  if (!pending) {
    try {
      matches = await matchesForTab(tab);
    } catch (_) {
      return { ok: false };
    }
  }
  const captions = Fill.choiceCaptions
    ? Fill.choiceCaptions(matches)
    : (Fill.choiceLabels(matches) || []).map((label) => ({ primary: label, note: "" }));
  const compact = matches.map((m, i) => {
    const item = captions[i] || {};
    const primary = item.primary || String(m.username || "").trim() || "未填账号";
    const note = item.note || "";
    return {
      id: m.id,
      title: m.title,
      username: m.username,
      notes: m.notes || "",
      has_totp: Boolean(m.has_totp),
      badge: m.has_totp ? "验证码" : "",
      primary,
      note,
      label: note ? `${primary} · ${note}` : primary,
    };
  });
  const decision = Fill.overlayDecision({
    pending,
    matches: compact,
    hasPassword: true,
    force: Boolean(pending),
  });
  if (decision.kind === "save") {
    const mounted = await injectOverlay(tab.id, { kind: "save", pending: decision.pending });
    if (!mounted?.painted) {
      return { ok: false, count: 1, painted: false, error: mounted?.error || "未能弹出保存/更新卡片" };
    }
    return { ok: true, count: 1, painted: true, kind: "save" };
  }
  if (decision.kind !== "fill") {
    await runOnTopFrame(tab.id, removeOverlayFunc);
    return { ok: true, count: 0, painted: false };
  }
  const mounted = await injectOverlay(tab.id, { kind: "fill", matches: compact });
  if (!mounted?.painted) {
    return { ok: false, count: compact.length, painted: false, error: mounted?.error || "无法在页面上显示填充卡片" };
  }
  return { ok: true, count: compact.length, painted: true, kind: "fill" };
}

async function overlayTab(sender) {
  const tabId = sender.tab?.id;
  if (!tabId) throw new Error("没有活动标签页");
  const tab = await chrome.tabs.get(tabId);
  return tab;
}

async function openFillOnTab(tab) {
  if (!tab?.id) throw new Error("没有活动标签页");
  const shown = await showOverlayOnTab(tab);
  if (shown?.ok && shown.count) return shown;
  if (shown?.ok && !shown.count) return { ok: true, count: 0 };
  return shown || { ok: false, error: "无法打开填充选择" };
}

const overlayTimers = new Map();
function scheduleOverlay(tabId, delayMs) {
  const prev = overlayTimers.get(tabId);
  if (prev) clearTimeout(prev);
  overlayTimers.set(
    tabId,
    setTimeout(() => {
      overlayTimers.delete(tabId);
      chrome.tabs.get(tabId, (tab) => {
        if (chrome.runtime.lastError || !tab) return;
        showOverlayOnTab(tab).catch(() => {});
      });
    }, delayMs),
  );
}

chrome.webNavigation.onCompleted.addListener((details) => {
  scheduleOverlay(details.tabId, details.frameId === 0 ? 600 : 400);
});
chrome.webNavigation.onDOMContentLoaded.addListener((details) => {
  scheduleOverlay(details.tabId, 400);
});
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "complete" || changeInfo.url) scheduleOverlay(tabId, 600);
});

async function fillTab(tabId, id, url) {
  if (!tabId) throw new Error("没有活动标签页");
  const data = await api("/fill/secret", { id, url });
  if (!data?.ok || !data.entry) throw new Error(data?.error || "无法读取凭据");
  await rememberFill(data.entry, url);
  const applied = await applySecretToTab(tabId, data.entry, url);
  if (!applied.ok) throw new Error(applied.error);
  return { ok: true };
}

chrome.commands?.onCommand.addListener((command) => {
  if (command !== "fill-current") return;
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    openFillOnTab(tabs[0]).catch(() => {});
  });
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    const pageUrl = senderPageUrl(sender, msg.url);
    if (msg.type === "pair") return pair(msg.code);
    if (msg.type === "status") return api("/fill/status", {});
    if (msg.type === "settings") return { ok: true, settings: await getSettings() };
    if (msg.type === "match") return api("/fill/match", { url: pageUrl });
    if (msg.type === "secret") {
      const data = await api("/fill/secret", { id: msg.id, url: pageUrl });
      if (data?.ok && data.entry) await rememberFill(data.entry, pageUrl);
      return data;
    }
    if (msg.type === "fill-secret") {
      const tabId = sender.tab?.id;
      if (!tabId) throw new Error("没有活动标签页");
      return fillTab(tabId, msg.id, pageUrl);
    }
    if (msg.type === "fill-tab") {
      const tab =
        sender.tab ||
        (await chrome.tabs.query({ active: true, currentWindow: true }).then((tabs) => tabs[0]));
      if (!tab?.id) throw new Error("没有活动标签页");
      if (!/^https?:/i.test(tab.url || "")) {
        throw new Error("当前页不是普通网页，无法填充。请先打开登录页。");
      }
      return fillTab(tab.id, msg.id, tab.url || msg.url || "");
    }
    if (msg.type === "inject-tab") {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return { ok: false };
      const injected = await injectTab(tab.id);
      return { ok: injected };
    }
    if (msg.type === "read-tab-fields") {
      const tabId = Number(msg.tabId) || (await chrome.tabs.query({ active: true, currentWindow: true }).then((tabs) => tabs[0]?.id));
      if (!tabId) return { ok: false, error: "没有活动标签页" };
      return readFieldsFromTab(tabId);
    }
    if (msg.type === "save") {
      const data = await api("/fill/save", {
        title: msg.title,
        url: pageUrl,
        username: msg.username,
        password: msg.password,
        notes: msg.notes || "",
      });
      await rememberFill({ username: msg.username, password: msg.password }, pageUrl);
      await sessionRemove(["pendingSave"]);
      return data;
    }
    if (msg.type === "capture-login") {
      const result = await captureLogin(msg.pendingSave, pageUrl, sender.tab?.id);
      if (result?.captured && sender.tab?.id) scheduleOverlay(sender.tab.id, 250);
      return result;
    }
    if (msg.type === "pending-save") return describePending(sender.tab ? pageUrl : "", sender.tab?.id);
    if (msg.type === "confirm-save") {
      const data = await confirmSave(pageUrl, Boolean(sender.tab), sender.tab?.id);
      const tabId =
        sender.tab?.id ||
        (await chrome.tabs.query({ active: true, currentWindow: true }).then((tabs) => tabs[0]?.id));
      if (tabId) scheduleOverlay(tabId, 50);
      return data;
    }
    if (msg.type === "clear-pending") {
      await sessionRemove(["pendingSave", "pendingTotp"]);
      const tabId = sender.tab?.id;
      if (tabId) scheduleOverlay(tabId, 50);
      return { ok: true };
    }
    if (msg.type === "exclude-site") {
      const pending = await getPending();
      const target = pending?.url || msg.url || pageUrl;
      return { ok: true, settings: await excludeSite(target) };
    }
    if (msg.type === "detect-page") {
      if (sender.tab?.id) scheduleOverlay(sender.tab.id, 250);
      return { ok: true };
    }
    if (msg.type === "open-fill-tab") {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      return openFillOnTab(tab);
    }
    if (msg.type === "overlay-init") {
      const tab = await overlayTab(sender);
      const matches = await matchesForTab(tab);
      return { ok: true, matches };
    }
    if (msg.type === "overlay-resize") {
      const tab = await overlayTab(sender);
      return runOnTopFrame(tab.id, resizeOverlayFunc, [msg.height]);
    }
    if (msg.type === "overlay-close") {
      const tab = await overlayTab(sender);
      return runOnTopFrame(tab.id, removeOverlayFunc);
    }
    throw new Error("unknown message");
  })()
    .then(sendResponse)
    .catch((e) => sendResponse({ ok: false, error: String(e.message || e) }));
  return true;
});
