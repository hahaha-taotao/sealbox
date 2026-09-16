(function (root) {
  const PENDING_TTL_MS = 5 * 60 * 1000;

  function stripWww(host) {
    return String(host || "")
      .trim()
      .toLowerCase()
      .replace(/^\[/, "")
      .replace(/\]$/, "")
      .replace(/^www\./, "");
  }

  function originOf(url) {
    const raw = String(url || "").trim();
    if (!raw) return null;
    try {
      const u = new URL(raw.includes("://") ? raw : `https://${raw}`);
      if (u.protocol !== "http:" && u.protocol !== "https:") return null;
      const host = stripWww(u.hostname);
      if (!host || host === "localhost" || !host.includes(".")) return null;
      const port = u.port ? Number(u.port) : u.protocol === "http:" ? 80 : 443;
      if (!Number.isFinite(port)) return null;
      return { scheme: u.protocol.replace(":", ""), host, port };
    } catch (_) {
      return null;
    }
  }

  function sameSite(a, b) {
    const oa = originOf(a);
    const ob = originOf(b);
    return Boolean(oa && ob && oa.scheme === ob.scheme && oa.host === ob.host && oa.port === ob.port);
  }

  function parseExcludeHosts(text) {
    return String(text || "")
      .split(/\r?\n/)
      .map((line) => line.trim().toLowerCase())
      .filter(Boolean)
      .filter((line) => !line.startsWith("#"));
  }

  function hostMatchesRule(host, rule) {
    const h = stripWww(host);
    let r = String(rule || "").trim().toLowerCase();
    if (!h || !r) return false;
    if (r.startsWith("*.")) {
      const suffix = stripWww(r.slice(2));
      return h === suffix || h.endsWith(`.${suffix}`);
    }
    r = stripWww(r);
    return h === r;
  }

  function isExcluded(url, rules) {
    const origin = originOf(url);
    if (!origin) return false;
    return (rules || []).some((rule) => hostMatchesRule(origin.host, rule));
  }

  function displayHost(url) {
    const origin = originOf(url);
    if (!origin) return "";
    if (origin.port === 80 || origin.port === 443) return origin.host;
    return `${origin.host}:${origin.port}`;
  }

  function abbreviateTitle(title, keep, short) {
    const chars = [...String(title || "").trim()];
    if (!chars.length) return "";
    const keepLen = keep == null ? 8 : keep;
    const shortLen = short == null ? 4 : short;
    if (chars.length <= keepLen) return chars.join("");
    return `${chars.slice(0, shortLen).join("")}…`;
  }

  function abbreviateNote(notes, keep, short) {
    const text = String(notes || "").replace(/\s+/g, " ").trim();
    if (!text) return "";
    const keepLen = keep == null ? 8 : keep;
    const shortLen = short == null ? 6 : short;
    const chars = [...text];
    if (chars.length <= keepLen) return chars.join("");
    return `${chars.slice(0, shortLen).join("")}…`;
  }

  function choiceLabel({ title, username, notes, hideTitle } = {}) {
    const user = String(username || "").trim() || "未填账号";
    const parts = [user];
    if (!hideTitle) {
      const shortTitle = abbreviateTitle(title);
      if (shortTitle && shortTitle !== user) parts.push(shortTitle);
    }
    const shortNote = abbreviateNote(notes);
    if (shortNote) parts.push(shortNote);
    return parts.join(" · ");
  }

  function choicePrimary({ title, username, hideTitle } = {}) {
    return choiceLabel({ title, username, hideTitle });
  }

  function choiceLabels(matches) {
    return choiceCaptions(matches).map((item) =>
      item.note ? `${item.primary} · ${item.note}` : item.primary,
    );
  }

  function choiceCaptions(matches) {
    const list = matches || [];
    const titles = new Set(list.map((m) => String(m.title || "").trim()).filter(Boolean));
    const hideTitle = titles.size <= 1;
    return list.map((m) => ({
      primary: choicePrimary({ title: m.title, username: m.username, hideTitle }),
      note: abbreviateNote(m.notes),
    }));
  }

  function addHostLine(text, hostOrUrl) {
    const origin = originOf(hostOrUrl);
    const host = origin ? origin.host : stripWww(hostOrUrl);
    if (!host) return String(text || "");
    const current = String(text || "");
    const rules = parseExcludeHosts(current);
    if (rules.some((rule) => hostMatchesRule(host, rule))) return current;
    const trimmed = current.trim();
    return trimmed ? `${trimmed}\n${host}` : host;
  }

  function classifySave(pending, matches, passwordMatches) {
    if (!pending || !String(pending.password || "")) return { action: "none" };
    const username = String(pending.username || "");
    const hits = (matches || []).filter((m) => String(m.username || "") === username);
    if (!hits.length) return { action: "save" };
    if (passwordMatches === true) return { action: "unchanged", match: hits[0] };
    return { action: "update", match: hits[0] };
  }

  function overlayDecision({ pending, matches, hasPassword, force } = {}) {
    const action = pending && pending.action;
    if (pending && action && action !== "none" && action !== "unchanged") {
      if (hasPassword || force) return { kind: "save", pending };
      return { kind: "none" };
    }
    const list = matches || [];
    if (hasPassword && list.length) return { kind: "fill", matches: list };
    return { kind: "none" };
  }

  function isPendingExpired(pending, now, ttlMs) {
    if (!pending || !pending.at) return true;
    const ttl = ttlMs == null ? PENDING_TTL_MS : ttlMs;
    return now - Number(pending.at) > ttl;
  }

  function isLoginActionText(text) {
    return /log[\s_-]*in|sign[\s_-]*in|submit|登录|登陆|signin|sign-in|next|继续|下一步/i.test(
      String(text || ""),
    );
  }

  function looksLikeSubmitControl(el) {
    const node =
      el && typeof el.closest === "function"
        ? el.closest("button, input, [role=button]")
        : null;
    if (!node) return false;
    const type = String(node.getAttribute("type") || "").toLowerCase();
    if (type === "submit" || type === "image") return true;
    const text = `${node.getAttribute("name") || ""} ${node.id || ""} ${node.className || ""} ${node.getAttribute("aria-label") || ""} ${node.textContent || ""} ${node.value || ""}`;
    return isLoginActionText(text);
  }

  function shouldSkipSavePrompt(pending, lastFilled, now) {
    if (!pending || !lastFilled || !lastFilled.url) return false;
    const t = now == null ? Date.now() : now;
    if (isPendingExpired(lastFilled, t)) return false;
    if (!sameSite(pending.url, lastFilled.url)) return false;
    return (
      String(pending.username || "") === String(lastFilled.username || "") &&
      String(pending.password || "") === String(lastFilled.password || "")
    );
  }

  function nativeValue(el) {
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
    if (el._v != null && String(el._v) !== "") return String(el._v);
    return "";
  }

  function pickSaveUrl(tabUrl, msgUrl) {
    if (msgUrl && tabUrl && sameSite(tabUrl, msgUrl)) return msgUrl;
    if (/^https?:/i.test(String(tabUrl || ""))) return tabUrl;
    return msgUrl || tabUrl || "";
  }

  function readFieldsScore(fields) {
    if (!fields) return -1;
    let n = 0;
    if (fields.ok) n += 1;
    if (fields.hasPassword) n += 10;
    if (String(fields.password || "")) n += 100;
    if (String(fields.username || "")) n += 50;
    return n;
  }

  function isPasswordLike(field) {
    const type = String(field.type || "").toLowerCase();
    const a = `${type} ${field.name || ""} ${field.id || ""} ${field.placeholder || ""} ${field.autocomplete || ""} ${field.className || ""}`;
    const masked = /disc|circle|square/i.test(String(field.textSecurity || ""));
    return type === "password" || masked || /password|passwd|pwd|secret|密码|口令/i.test(a);
  }

  function passwordScore(field) {
    if (!field || !isPasswordLike(field)) return -1;
    let n = 10;
    if (String(field.type || "").toLowerCase() === "password") n += 20;
    if (/disc|circle|square/i.test(String(field.textSecurity || ""))) n += 25;
    if (String(field.value || "")) n += 100;
    if (field.rendered) n += 20;
    if (field.hidden || field.disabled) n -= 40;
    const auto = String(field.autocomplete || "");
    if (/new-password/i.test(auto)) n -= 20;
    if (/current-password/i.test(auto)) n += 10;
    return n;
  }

  function usernameScore(field) {
    if (!field || isPasswordLike(field)) return -1;
    const type = String(field.type || "").toLowerCase();
    if (["hidden", "submit", "button", "checkbox", "radio", "file", "image", "reset"].includes(type)) {
      return -1;
    }
    const value = String(field.value || "").trim();
    if (field.hidden && !value) return -1;
    let n = 0;
    if (value) n += 100;
    if (field.rendered) n += 20;
    else n -= 10;
    if (field.hidden) n -= 50;
    if (field.disabled || field.readOnly) n -= 5;
    if (type === "email" || type === "tel") n += 15;
    const a = `${field.name || ""} ${field.id || ""} ${field.placeholder || ""} ${field.autocomplete || ""} ${field.className || ""} ${field.ariaLabel || ""}`;
    if (/user|login|email|account|phone|mobile|账号|用户|工号|手机/i.test(a)) n += 30;
    if (/^1\d{10}$/.test(value) || /@/.test(value)) n += 20;
    if (type === "text" || type === "number" || type === "search" || type === "tel" || !type) n += 5;
    return n;
  }

  function pickLoginValues(fields) {
    const list = fields || [];
    let passwordIndex = -1;
    let bestPwd = -1;
    for (let i = 0; i < list.length; i += 1) {
      const score = passwordScore(list[i]);
      if (score > bestPwd) {
        bestPwd = score;
        passwordIndex = i;
      }
    }
    let usernameIndex = -1;
    let bestUser = -1;
    for (let i = 0; i < list.length; i += 1) {
      if (i === passwordIndex) continue;
      const score = usernameScore(list[i]);
      if (score > bestUser) {
        bestUser = score;
        usernameIndex = i;
      }
    }
    if (bestPwd < 0 && bestUser < 0) {
      return { ok: true, hasPassword: false, username: "", password: "", usernameIndex: -1, passwordIndex: -1 };
    }
    return {
      ok: true,
      hasPassword: bestPwd >= 0,
      username: usernameIndex >= 0 ? String(list[usernameIndex].value || "") : "",
      password: passwordIndex >= 0 ? String(list[passwordIndex].value || "") : "",
      usernameIndex,
      passwordIndex,
    };
  }

  function fillTokenFromStores({ sessionToken, localToken } = {}) {
    const session = String(sessionToken || "");
    const local = String(localToken || "");
    return {
      token: session || local,
      writeSession: Boolean(!session && local),
      removeLocal: Boolean(local),
    };
  }

  function fillTokenWritePlan(fillToken) {
    return {
      token: String(fillToken || ""),
      writeSession: true,
      removeLocal: true,
    };
  }

  function pickReadFields(replies) {
    const list = (replies || []).filter(Boolean);
    if (!list.length) return { ok: false };
    let bestUser = null;
    let bestUserScore = -1;
    let bestPwd = null;
    let bestPwdScore = -1;
    for (const item of list) {
      const username = String(item.username || "");
      const password = String(item.password || "");
      const userScore = (username ? 50 : 0) + readFieldsScore(item);
      const pwdScore = (password ? 100 : 0) + (item.hasPassword ? 10 : 0);
      if (username && userScore > bestUserScore) {
        bestUser = item;
        bestUserScore = userScore;
      }
      if ((password || item.hasPassword) && pwdScore > bestPwdScore) {
        bestPwd = item;
        bestPwdScore = pwdScore;
      }
    }
    if (!bestPwd && !bestUser) return { ok: false };
    return {
      ok: true,
      username: String(bestUser?.username || bestPwd?.username || ""),
      password: String(bestPwd?.password || ""),
      hasPassword: Boolean(bestPwd?.hasPassword || bestPwd?.password),
    };
  }

  const api = {
    PENDING_TTL_MS,
    stripWww,
    originOf,
    sameSite,
    parseExcludeHosts,
    isExcluded,
    displayHost,
    abbreviateTitle,
    abbreviateNote,
    choicePrimary,
    choiceLabel,
    choiceLabels,
    choiceCaptions,
    addHostLine,
    classifySave,
    overlayDecision,
    isPendingExpired,
    shouldSkipSavePrompt,
    isLoginActionText,
    looksLikeSubmitControl,
    pickSaveUrl,
    nativeValue,
    pickLoginValues,
    pickReadFields,
    fillTokenFromStores,
    fillTokenWritePlan,
  };

  root.SealboxFill = api;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
