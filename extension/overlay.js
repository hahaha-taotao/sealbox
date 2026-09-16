function showError(text) {
  const el = document.getElementById("error");
  el.hidden = !text;
  el.textContent = text || "";
}

function resize() {
  const card = document.getElementById("card");
  const height = Math.ceil(card.getBoundingClientRect().height + 8);
  chrome.runtime.sendMessage({ type: "overlay-resize", height }).catch(() => {});
}

function render(matches) {
  const list = document.getElementById("list");
  list.innerHTML = "";
  const items = matches || [];
  document.getElementById("title").textContent =
    items.length > 1 ? `Sealbox · ${items.length} 个匹配` : "Sealbox · 填充";
  items.slice(0, 8).forEach((m) => {
    const b = document.createElement("button");
    b.type = "button";
    const primary = document.createElement("span");
    primary.textContent = m.primary || m.username || m.title || "未填账号";
    primary.style.cssText = "display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;";
    b.appendChild(primary);
    const note = String(m.note || m.notes || "").replace(/\s+/g, " ").trim();
    if (note) {
      const noteEl = document.createElement("span");
      const chars = [...note];
      noteEl.textContent = chars.length <= 8 ? note : `${chars.slice(0, 6).join("")}…`;
      noteEl.style.cssText =
        "display:block;margin-top:2px;font-size:11px;line-height:1.3;color:rgba(255,255,255,.72);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;";
      b.appendChild(noteEl);
    }
    b.onclick = async () => {
      showError("");
      const res = await chrome.runtime.sendMessage({ type: "fill-tab", id: m.id });
      if (!res?.ok) {
        showError(res?.error || "填充失败");
        resize();
        return;
      }
      chrome.runtime.sendMessage({ type: "overlay-close" }).catch(() => {});
    };
    list.appendChild(b);
  });
  resize();
}

document.getElementById("close").onclick = () => {
  chrome.runtime.sendMessage({ type: "overlay-close" }).catch(() => {});
};

chrome.runtime.sendMessage({ type: "overlay-init" }).then((res) => {
  render(res?.matches || []);
  if (!res?.ok && res?.error) showError(res.error);
  resize();
});
