function isVisible(el) {
  if (!el || el.disabled || el.readOnly) return false;
  const st = getComputedStyle(el);
  if (st.display === "none" || st.visibility === "hidden" || Number(st.opacity) === 0) return false;
  const r = el.getBoundingClientRect();
  return r.width > 8 && r.height > 8;
}

function allInputs(root = document) {
  return [...root.querySelectorAll("input, textarea")];
}

function findFields(root = document) {
  const passwords = allInputs(root)
    .filter((el) => el instanceof HTMLInputElement)
    .filter((el) => el.type === "password" || el.autocomplete === "current-password" || el.autocomplete === "new-password")
    .filter(isVisible);
  if (!passwords.length) return null;
  const password = passwords[passwords.length - 1];
  const form = password.form;
  const scope = form || root;
  const candidates = allInputs(scope)
    .filter((el) => el instanceof HTMLInputElement)
    .filter(isVisible)
    .filter((el) => el !== password && el.type !== "hidden" && el.type !== "submit" && el.type !== "button");
  const user =
    candidates.find((el) => el.type === "email") ||
    candidates.find((el) => /user|login|email|account|phone|mobile/i.test(`${el.name} ${el.id} ${el.placeholder} ${el.autocomplete}`)) ||
    candidates.find((el) => el.type === "text" || el.type === "tel") ||
    null;
  return { user, password, form };
}

function setValue(el, value) {
  if (!el) return;
  el.focus();
  const proto = HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
  setter ? setter.call(el, value) : (el.value = value);
  el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, data: value }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  el.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));
}

function bar() {
  let el = document.getElementById("sealbox-bar");
  if (el) return el;
  el = document.createElement("div");
  el.id = "sealbox-bar";
  el.style.cssText =
    "position:fixed;z-index:2147483647;right:16px;bottom:16px;background:#1f2329;color:#fff;padding:10px 12px;border-radius:10px;font:13px/1.4 Segoe UI,sans-serif;box-shadow:0 8px 24px rgba(0,0,0,.25);max-width:280px;";
  (document.body || document.documentElement).appendChild(el);
  return el;
}

function hideBar() {
  document.getElementById("sealbox-bar")?.remove();
}

async function fillId(id) {
  const res = await chrome.runtime.sendMessage({ type: "secret", id });
  if (!res?.ok) throw new Error(res?.error || "无法读取凭据");
  const fields = findFields() || findFieldsInFrames();
  if (!fields) throw new Error("页面上没有密码框");
  setValue(fields.user, res.entry.username);
  setValue(fields.password, res.entry.password);
  hideBar();
}

function findFieldsInFrames() {
  const top = findFields(document);
  if (top) return top;
  for (const f of document.querySelectorAll("iframe")) {
    try {
      const doc = f.contentDocument;
      if (doc) {
        const inner = findFields(doc);
        if (inner) return inner;
      }
    } catch (_) {
      /* cross-origin */
    }
  }
  return null;
}

let lastKey = "";
async function detect() {
  const fields = findFieldsInFrames();
  if (!fields) return;
  const res = await chrome.runtime.sendMessage({ type: "match", url: location.href });
  if (!res?.ok) return;
  const key = (res.matches || []).map((m) => m.id).join(",");
  if (key === lastKey && document.getElementById("sealbox-bar")) return;
  lastKey = key;
  if (!res.matches?.length) {
    hideBar();
    return;
  }
  const el = bar();
  el.innerHTML = "";
  const title = document.createElement("div");
  title.textContent = `Sealbox · ${res.matches.length} 个匹配`;
  title.style.marginBottom = "6px";
  el.appendChild(title);
  res.matches.slice(0, 5).forEach((m) => {
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
  document.addEventListener(
    "submit",
    (e) => {
      const form = e.target instanceof HTMLFormElement ? e.target : null;
      const fields = (form && findFields(form)) || findFieldsInFrames();
      if (!fields?.password?.value) return;
      chrome.storage.session.set({
        pendingSave: {
          url: location.href,
          title: document.title,
          username: fields.user?.value || "",
          password: fields.password.value,
        },
      });
    },
    true,
  );
}

detect().catch(() => {});
captureSubmit();
const mo = new MutationObserver(() => detect().catch(() => {}));
mo.observe(document.documentElement, { childList: true, subtree: true });
setInterval(() => detect().catch(() => {}), 2500);

chrome.runtime.onMessage.addListener((msg, _s, sendResponse) => {
  if (msg.type === "fill-now") {
    fillId(msg.id)
      .then(() => sendResponse({ ok: true }))
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }
  if (msg.type === "read-fields") {
    const f = findFieldsInFrames();
    sendResponse({
      ok: true,
      username: f?.user?.value || "",
      password: f?.password?.value || "",
      hasPassword: Boolean(f?.password),
    });
  }
});
