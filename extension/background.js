const DEFAULT_PORT = 17891;

async function pair() {
  const stored = await chrome.storage.local.get(["port"]);
  const port = stored.port || DEFAULT_PORT;
  const res = await fetch(`http://127.0.0.1:${port}/fill/pair`, { method: "POST" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.fillToken) {
    if (res.status === 403) throw new Error("金库已锁定，请先解锁 Sealbox");
    throw new Error(data.error || "无法连接 Sealbox，请确认应用已启动");
  }
  await chrome.storage.local.set({ fillToken: data.fillToken, port: data.port || port });
  return { port: data.port || port, fillToken: data.fillToken };
}

async function settings() {
  const s = await chrome.storage.local.get(["port", "fillToken"]);
  if (s.fillToken) {
    return { port: s.port || DEFAULT_PORT, fillToken: s.fillToken };
  }
  return pair();
}

async function api(path, body) {
  let { port, fillToken } = await settings();
  const call = (token) =>
    fetch(`http://127.0.0.1:${port}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body || {}),
    });
  let res = await call(fillToken);
  if (res.status === 401) {
    const fresh = await pair();
    port = fresh.port;
    fillToken = fresh.fillToken;
    res = await call(fillToken);
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.ok === false) {
    if (res.status === 403) throw new Error("金库已锁定，请先解锁 Sealbox");
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (msg.type === "pair") return pair();
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
