function isVisible(el) {
  if (!el) return false;
  const st = getComputedStyle(el);
  if (st.display === "none" || st.visibility === "hidden" || st.opacity === "0") return false;
  const r = el.getBoundingClientRect();
  return r.width > 0 && r.height > 0;
}

function findFields() {
  const passwords = [...document.querySelectorAll('input[type="password"]')].filter(isVisible);
  if (!passwords.length) return null;
  const password = passwords[passwords.length - 1];
  const form = password.form;
  const scope = form || document;
  const user =
    scope.querySelector('input[type="email"]') ||
    scope.querySelector('input[name*="user" i]') ||
    scope.querySelector('input[name*="login" i]') ||
    scope.querySelector('input[name*="email" i]') ||
    scope.querySelector('input[autocomplete="username"]') ||
    [...scope.querySelectorAll('input[type="text"]')].filter(isVisible)[0] ||
    null;
  return { user, password, form };
}

function setValue(el, value) {
  if (!el) return;
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
  setter ? setter.call(el, value) : (el.value = value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}

function bar() {
  let el = document.getElementById("sealbox-bar");
  if (el) return el;
  el = document.createElement("div");
  el.id = "sealbox-bar";
  el.style.cssText =
    "position:fixed;z-index:2147483647;right:16px;bottom:16px;background:#1f2329;color:#fff;padding:10px 12px;border-radius:10px;font:13px/1.4 Segoe UI,sans-serif;box-shadow:0 8px 24px rgba(0,0,0,.25);max-width:280px;";
  document.documentElement.appendChild(el);
  return el;
}

function hideBar() {
  document.getElementById("sealbox-bar")?.remove();
}

async function fillId(id) {
  const res = await chrome.runtime.sendMessage({ type: "secret", id });
  if (!res?.ok) throw new Error(res?.error || "无法读取凭据");
  const fields = findFields();
  if (!fields) throw new Error("页面上没有密码框");
  setValue(fields.user, res.entry.username);
  setValue(fields.password, res.entry.password);
  hideBar();
}

async function detect() {
  const fields = findFields();
  if (!fields) return;
  const res = await chrome.runtime.sendMessage({ type: "match", url: location.href });
  if (!res?.ok || !res.matches?.length) return;
  const el = bar();
  el.innerHTML = "";
  const title = document.createElement("div");
  title.textContent = `Sealbox · ${res.matches.length} 个匹配`;
  title.style.marginBottom = "6px";
  el.appendChild(title);
  res.matches.slice(0, 4).forEach((m) => {
    const b = document.createElement("button");
    b.textContent = `填充 ${m.username || m.title}`;
    b.style.cssText =
      "display:block;width:100%;margin:4px 0;padding:6px 8px;border:0;border-radius:6px;background:#5b5bd6;color:#fff;cursor:pointer;";
    b.onclick = () => fillId(m.id).catch((e) => alert(e.message));
    el.appendChild(b);
  });
  const x = document.createElement("button");
  x.textContent = "关闭";
  x.style.cssText = "margin-top:4px;border:0;background:transparent;color:#aaa;cursor:pointer;";
  x.onclick = hideBar;
  el.appendChild(x);
}

function captureSubmit() {
  const fields = findFields();
  if (!fields?.form) return;
  fields.form.addEventListener(
    "submit",
    () => {
      const username = fields.user?.value || "";
      const password = fields.password?.value || "";
      if (!password) return;
      chrome.runtime.sendMessage({
        type: "maybe-save",
        url: location.href,
        title: document.title,
        username,
        password,
      });
      chrome.storage.session.set({
        pendingSave: { url: location.href, title: document.title, username, password },
      });
    },
    { capture: true },
  );
}

detect().catch(() => {});
captureSubmit();
setTimeout(() => detect().catch(() => {}), 1500);

chrome.runtime.onMessage.addListener((msg, _s, sendResponse) => {
  if (msg.type === "fill-now") {
    fillId(msg.id)
      .then(() => sendResponse({ ok: true }))
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }
  if (msg.type === "read-fields") {
    const f = findFields();
    sendResponse({
      ok: true,
      username: f?.user?.value || "",
      password: f?.password?.value || "",
      hasPassword: Boolean(f?.password),
    });
  }
});
