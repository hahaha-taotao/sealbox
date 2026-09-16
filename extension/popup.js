async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function showError(msg) {
  document.getElementById("status").innerHTML = `<span id="error">${escapeHtml(msg)}</span>`;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function setMsg(id, text, kind) {
  const el = document.getElementById(id);
  el.hidden = !text;
  el.textContent = text || "";
  el.className = kind === "error" ? "msg error" : "msg";
}

let persistTimer = 0;

async function send(msg, timeoutMs = 8000) {
  return Promise.race([
    chrome.runtime.sendMessage(msg),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("扩展后台无响应，请到 chrome://extensions 重新加载 Sealbox")), timeoutMs),
    ),
  ]);
}

document.getElementById("pair").onclick = async () => {
  const btn = document.getElementById("pair");
  const code = document.getElementById("code").value;
  if (!String(code || "").trim()) return showError("请输入一次性配对码");
  btn.disabled = true;
  document.getElementById("status").textContent = "正在配对…";
  try {
    const res = await send({ type: "pair", code });
    if (!res?.ok) return showError(res?.error || "配对失败");
    document.getElementById("code").value = "";
    document.getElementById("status").textContent = "已配对";
    await refresh();
  } catch (e) {
    showError(String(e.message || e));
  } finally {
    btn.disabled = false;
  }
};

document.getElementById("save").onclick = async () => {
  const tab = await currentTab();
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  if (!password) {
    setMsg("save-msg", "请先填写密码再登记", "error");
    return;
  }
  setMsg("save-msg", "正在写入金库…");
  const res = await send({
    type: "save",
    title: document.getElementById("title").value || tab?.title || "",
    url: tab?.url || "",
    username,
    password,
    notes: document.getElementById("notes").value,
  });
  if (!res?.ok) {
    setMsg("save-msg", res?.error || "登记失败", "error");
    showError(res?.error || "登记失败");
    return;
  }
  document.getElementById("status").textContent = "已写入金库";
  document.getElementById("password").value = "";
  setMsg("save-msg", "已写入金库");
  refresh();
};

document.getElementById("fill-now").onclick = async () => {
  const res = await send({ type: "open-fill-tab" }, 12000);
  if (!res?.ok || !res.painted) return showError(res?.error || "无法打开填充选择");
  if (!res.count) return showError("当前页没有可填充的网站账号");
  window.close();
};

async function persistExclude() {
  try {
    await chrome.storage.local.set({ excludeText: document.getElementById("exclude").value });
    setMsg("settings-msg", "排除列表已保存");
    return true;
  } catch (e) {
    setMsg("settings-msg", String(e.message || e), "error");
    return false;
  }
}

document.getElementById("exclude").addEventListener("input", () => {
  setMsg("settings-msg", "");
  clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    persistExclude();
  }, 300);
});

async function ensureContent(tabId) {
  if (!tabId) return;
  await send({ type: "inject-tab" }).catch(() => {});
}

function renderPending(pending) {
  const box = document.getElementById("pending");
  if (!pending) {
    box.hidden = true;
    box.innerHTML = "";
    return;
  }
  box.hidden = false;
  box.innerHTML = "";
  const title = document.createElement("div");
  title.className = "pending-title";
  title.textContent = pending.action === "update" ? "登录后：更新此密码？" : "登录后：保存此密码？";
  const meta = document.createElement("div");
  meta.className = "hint";
  meta.textContent = `${pending.username || "未填账号"} · ${pending.title || pending.url || ""}`;
  const row = document.createElement("div");
  row.className = "pending-actions";
  const ok = document.createElement("button");
  ok.textContent = pending.action === "update" ? "更新" : "保存";
  ok.onclick = async () => {
    const res = await send({ type: "confirm-save" });
    if (!res?.ok) return showError(res?.error || "保存失败");
    document.getElementById("status").textContent = "已写入金库";
    renderPending(null);
    refresh();
  };
  const skip = document.createElement("button");
  skip.className = "ghost";
  skip.textContent = "忽略";
  skip.onclick = async () => {
    await send({ type: "clear-pending" });
    renderPending(null);
  };
  row.appendChild(ok);
  row.appendChild(skip);
  box.appendChild(title);
  box.appendChild(meta);
  box.appendChild(row);
}

async function refresh() {
  const tab = await currentTab();
  document.getElementById("title").value = tab?.title || "";
  try {
    const stored = await chrome.storage.local.get(["excludeText"]);
    document.getElementById("exclude").value = stored.excludeText || "";
    const st = await send({ type: "status" });
    if (!st) return showError("扩展后台无响应，请到 chrome://extensions 重新加载 Sealbox");
    if (!st?.ok) return showError(st?.error || "无法连接 Sealbox，请确认应用已启动并完成配对");
    if (!st.unlocked) return showError("金库已锁定，请先解锁 Sealbox");
    document.getElementById("status").textContent = "已配对 · 金库已解锁";
    const pending = await send({ type: "pending-save" });
    renderPending(pending?.pending);
    const m = await send({ type: "match", url: tab?.url || "" });
    const box = document.getElementById("matches");
    box.innerHTML = "";
    (m.matches || []).forEach((item) => {
      const row = document.createElement("div");
      row.className = "match";
      const label = document.createElement("span");
      const strong = document.createElement("strong");
      strong.textContent = item.username || "未填账号";
      const small = document.createElement("small");
      const note = String(item.notes || "").replace(/\s+/g, " ").trim();
      const noteChars = [...note];
      small.textContent = noteChars.length > 8 ? `${noteChars.slice(0, 6).join("")}…` : note;
      label.appendChild(strong);
      if (small.textContent) {
        label.appendChild(document.createElement("br"));
        label.appendChild(small);
      }
      row.appendChild(label);
      const btn = document.createElement("button");
      btn.textContent = "填充";
      btn.onclick = async () => {
        try {
          const r = await send({ type: "fill-tab", id: item.id, url: tab.url });
          if (!r?.ok) showError(r?.error || "填充失败");
          else window.close();
        } catch (e) {
          showError(String(e.message || e) || "当前页无法注入脚本（浏览器内部页或不支持）");
        }
      };
      row.appendChild(btn);
      box.appendChild(row);
    });
    if (!(m.matches || []).length) {
      box.textContent = "当前地址没有匹配的网站账号。请确认条目类型是「网站账号」，网址含该站点域名。";
    }
    const fields = tab?.id
      ? await send({ type: "read-tab-fields", tabId: tab.id }, 4000).catch(() => null)
      : null;
    if (fields?.ok === false && fields?.error) {
      setMsg("save-msg", fields.error, "error");
    } else if (fields?.username || fields?.password) {
      if (fields.username) document.getElementById("username").value = fields.username;
      if (fields.password) document.getElementById("password").value = fields.password;
      setMsg("save-msg", "");
    } else {
      setMsg("save-msg", "未能读取当前页账号密码，可手动填写后登记");
    }
    if ((m.matches || []).length) {
      send({ type: "open-fill-tab" }).catch(() => {});
    }
  } catch (e) {
    showError(String(e.message || e));
  }
}

refresh();
