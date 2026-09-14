async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function showError(msg) {
  document.getElementById("status").innerHTML = `<span id="error">${msg}</span>`;
}

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

async function ensureContent(tabId) {
  try {
    await chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] });
  } catch (_) {
    /* restricted page */
  }
}

async function refresh() {
  const tab = await currentTab();
  document.getElementById("title").value = tab?.title || "";
  if (tab?.id) await ensureContent(tab.id);
  try {
    const paired = await chrome.runtime.sendMessage({ type: "pair" });
    if (!paired?.fillToken && !paired?.ok && paired?.error) {
      return showError(paired.error);
    }
    const st = await chrome.runtime.sendMessage({ type: "status" });
    if (!st?.ok) return showError(st?.error || "无法连接 Sealbox，请确认应用已启动并解锁");
    if (!st.unlocked) return showError("金库已锁定，请先解锁 Sealbox");
    document.getElementById("status").textContent = "已自动连接 · 金库已解锁";
    const m = await chrome.runtime.sendMessage({ type: "match", url: tab?.url || "" });
    const box = document.getElementById("matches");
    box.innerHTML = "";
    (m.matches || []).forEach((item) => {
      const row = document.createElement("div");
      row.className = "match";
      row.innerHTML = `<span>${item.title}<br><small>${item.username || ""}</small></span>`;
      const btn = document.createElement("button");
      btn.textContent = "填充";
      btn.onclick = async () => {
        try {
          const r = await chrome.tabs.sendMessage(tab.id, { type: "fill-now", id: item.id });
          if (!r?.ok) showError(r?.error || "填充失败");
          else window.close();
        } catch (_) {
          showError("当前页无法注入脚本（浏览器内部页或不支持）");
        }
      };
      row.appendChild(btn);
      box.appendChild(row);
    });
    if (!(m.matches || []).length) {
      box.textContent = "当前地址没有匹配的网站账号。请确认条目类型是「网站账号」，网址含该站点域名。";
    }
    const fields = await chrome.tabs.sendMessage(tab.id, { type: "read-fields" }).catch(() => null);
    if (fields?.username) document.getElementById("username").value = fields.username;
    if (fields?.password) document.getElementById("password").value = fields.password;
  } catch (e) {
    showError(String(e.message || e));
  }
}

refresh();
