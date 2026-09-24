(() => {
const SCRIPT_VERSION = 8;
if (globalThis.__sealboxContent === SCRIPT_VERSION) return;
const Fill = globalThis.SealboxFill;
const PageFill = globalThis.SealboxPageFill;
globalThis.__sealboxContent = SCRIPT_VERSION;

const FILL_SHORTCUT = { key: "f" };
const findFields = (root) => PageFill?.findFields?.(root || document) || null;

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

async function fillId(id) {
  const res = await chrome.runtime.sendMessage({ type: "fill-secret", id });
  if (!res?.ok) throw new Error(res?.error || "无法填充");
  document.getElementById("sealbox-overlay-host")?.remove();
}

function captureLogin(fields) {
  if (!fields?.password?.value) return;
  chrome.runtime.sendMessage({
    type: "capture-login",
    pendingSave: {
      url: location.href,
      title: document.title,
      username: fields.user?.value || "",
      password: fields.password.value,
      at: Date.now(),
    },
  });
}

function captureSubmit() {
  document.addEventListener(
    "submit",
    (e) => {
      const form = e.target instanceof HTMLFormElement ? e.target : null;
      const fields = (form && findFields(form)) || findFieldsInFrames();
      captureLogin(fields);
    },
    true,
  );
  document.addEventListener(
    "click",
    (e) => {
      const t = e.target instanceof Element ? e.target : e.target?.parentElement;
      if (!Fill?.looksLikeSubmitControl?.(t)) return;
      const form = t.closest("form");
      const fields = (form && findFields(form)) || findFieldsInFrames();
      captureLogin(fields);
    },
    true,
  );
}

function isFillShortcut(e) {
  return (
    e.altKey &&
    e.shiftKey &&
    !e.ctrlKey &&
    !e.metaKey &&
    String(e.key || "").toLowerCase() === FILL_SHORTCUT.key
  );
}

async function openFillChooser() {
  return chrome.runtime.sendMessage({ type: "open-fill-tab" });
}

window.addEventListener(
  "keydown",
  (e) => {
    if (!e.isTrusted || !isFillShortcut(e)) return;
    e.preventDefault();
    openFillChooser().catch((err) => alert(err.message));
  },
  true,
);
window.addEventListener("message", (e) => {
  if (e.source !== window) return;
  const data = e.data;
  if (!data || data.source !== "sealbox-overlay" || data.type !== "fill-tab") return;
  chrome.runtime.sendMessage({ type: "fill-tab", id: data.id }, (res) => {
    if (res?.ok) document.getElementById("sealbox-overlay-host")?.remove();
  });
});

function detect() {
  if (!findFieldsInFrames()) return;
  chrome.runtime.sendMessage({ type: "detect-page" }).catch(() => {});
}

let detectTimer = 0;
function startDetect() {
  if (detectTimer) return;
  detectTimer = setTimeout(() => {
    detectTimer = 0;
    detect();
  }, 250);
}

function isSealboxNode(node) {
  if (!(node instanceof Element)) return false;
  return (
    node.id === "sealbox-overlay-host" ||
    node.id === "sealbox-bar" ||
    Boolean(node.closest?.("#sealbox-overlay-host, #sealbox-bar"))
  );
}

startDetect();
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", startDetect, { once: true });
}
window.addEventListener("load", startDetect, { once: true });
captureSubmit();
const mo = new MutationObserver((muts) => {
  for (const m of muts) {
    const nodes = [...m.addedNodes, ...m.removedNodes, m.target];
    if (nodes.some((n) => !isSealboxNode(n))) {
      startDetect();
      return;
    }
  }
});
mo.observe(document.documentElement, { childList: true, subtree: true });
setInterval(startDetect, 2500);

chrome.runtime.onMessage.addListener((msg, _s, sendResponse) => {
  if (msg.type === "fill-now") {
    fillId(msg.id)
      .then(() => sendResponse({ ok: true }))
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }
  if (msg.type === "apply-secret") {
    sendResponse(PageFill?.fill?.(msg.username, msg.password, msg.totp) || { ok: false, error: "no-page-fill" });
    return;
  }
  if (msg.type === "open-fill") {
    openFillChooser()
      .then((r) => sendResponse(r))
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }
  if (msg.type === "read-fields") {
    sendResponse(PageFill?.readFields?.() || { ok: false, hasPassword: false });
  }
});
})();
