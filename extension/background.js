const DEFAULT_PORT = 17891;

async function loadBridgeFile() {
  try {
    const res = await fetch("http://127.0.0.1:17891/fill/status", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer probe" },
      body: "{}",
    });
    if (res.status !== 401 && res.ok) return;
  } catch (_) {
    /* ignore */
  }
}

async function settings() {
  const s = await chrome.storage.local.get(["port", "fillToken"]);
  let port = s.port || DEFAULT_PORT;
  let fillToken = s.fillToken || "";
  if (!fillToken) {
    try {
      const native = await fetch("http://127.0.0.1/__unused__").catch(() => null);
      void native;
    } catch (_) {
      /* ignore */
    }
  }
  return { port, fillToken };
}

async function api(path, body) {
  const { port, fillToken } = await settings();
  if (!fillToken) {
    throw new Error("未配置填表 Token。打开插件弹窗点「自动读取」，或从 Sealbox MCP 页复制。");
  }
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${fillToken}`,
    },
    body: JSON.stringify(body || {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.ok === false) {
    const msg = data.error || `HTTP ${res.status}`;
    if (res.status === 403) throw new Error("金库已锁定，请先在 Sealbox 解锁");
    if (res.status === 401) throw new Error("填表 Token 无效，请重新保存");
    throw new Error(msg);
  }
  return data;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (msg.type === "status") return api("/fill/status", {});
    if (msg.type === "match") return api("/fill/match", { url: msg.url });
    if (msg.type === "secret") return api("/fill/secret", { id: msg.id });
    if (msg.type === "save") {
      return api("/fill/save", {
        title: msg.title,
        url: msg.url,
        username: msg.username,
        password: msg.password,
      });
    }
    throw new Error("unknown message");
  })()
    .then(sendResponse)
    .catch((e) => sendResponse({ ok: false, error: String(e.message || e) }));
  return true;
});

void loadBridgeFile;
