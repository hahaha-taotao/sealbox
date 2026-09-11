async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function showError(msg) {
  document.getElementById("status").innerHTML = `<span id="error">${msg}</span>`;
}

async function loadCfg() {
  const s = await chrome.storage.local.get(["fillToken", "port"]);
  document.getElementById("token").value = s.fillToken || "";
  document.getElementById("port").value = s.port || "";
}

document.getElementById("saveCfg").onclick = async () => {
  await chrome.storage.local.set({
    fillToken: document.getElementById("token").value.trim(),
    port: Number(document.getElementById("port").value) || 17891,
  });
  document.getElementById("status").textContent = "连接已保存";
  refresh();
};

document.getElementById("save").onclick = async () => {
  const tab = await currentTab();
  const res = await chrome.runtime.sendMessage({
    type: "save",
    title: document.getElementById("title").value || tab?.title || "",
    url: tab?.url || "",
    username: document.getElementById("username").value,
    password: document.getElementById("password").value,
  });
  if (!res?.ok) return showError(res?.error || "登记失败");
  document.getElementById("status").textContent = "已写入金库";
  refresh();
};

async function refresh() {
  const tab = await currentTab();
  document.getElementById("title").value = tab?.title || "";
  try {
    const st = await chrome.runtime.sendMessage({ type: "status" });
    if (!st?.ok) return showError(st?.error || "无法连接 Sealbox");
    if (!st.unlocked) return showError("金库已锁定，请先解锁 Sealbox");
    document.getElementById("status").textContent = "已连接 · 金库已解锁";
    const m = await chrome.runtime.sendMessage({ type: "match", url: tab?.url || "" });
    const box = document.getElementById("matches");
    box.innerHTML = "";
    (m.matches || []).forEach((item) => {
      const row = document.createElement("div");
      row.className = "match";
      row.innerHTML = `<span>${item.title}<br><small>${item.username}</small></span>`;
      const btn = document.createElement("button");
      btn.textContent = "填充";
      btn.onclick = async () => {
        const r = await chrome.tabs.sendMessage(tab.id, { type: "fill-now", id: item.id });
        if (!r?.ok) showError(r?.error || "填充失败");
        else window.close();
      };
      row.appendChild(btn);
      box.appendChild(row);
    });
    if (!(m.matches || []).length) {
      box.textContent = "当前地址没有匹配的网站账号";
    }
    const fields = await chrome.tabs.sendMessage(tab.id, { type: "read-fields" }).catch(() => null);
    if (fields?.username) document.getElementById("username").value = fields.username;
    if (fields?.password) document.getElementById("password").value = fields.password;
  } catch (e) {
    showError(String(e.message || e));
  }
}

loadCfg().then(refresh);
