(() => {
  const HOST_ID = "sealbox-overlay-host";

  function collectInputs(root, acc) {
    if (!root) return acc;
    try {
      for (const el of root.querySelectorAll("input, textarea")) acc.push(el);
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) collectInputs(el.shadowRoot, acc);
      }
    } catch (_) {
      /* closed shadow */
    }
    return acc;
  }

  function hasPasswordField() {
    return collectInputs(document, []).some((el) => {
      const type = String(el.type || "").toLowerCase();
      const a = `${type} ${el.name || ""} ${el.id || ""} ${el.placeholder || ""} ${el.autocomplete || ""}`;
      return type === "password" || /password|passwd|pwd|secret|密码|口令/i.test(a);
    });
  }

  function remove() {
    document.getElementById(HOST_ID)?.remove();
  }

  function host() {
    let el = document.getElementById(HOST_ID);
    if (el?.shadowRoot) return el;
    el?.remove();
    el = document.createElement("div");
    el.id = HOST_ID;
    el.style.cssText = [
      "all:initial",
      "position:fixed !important",
      "z-index:2147483647 !important",
      "right:16px !important",
      "bottom:16px !important",
      "left:auto !important",
      "top:auto !important",
      "width:280px !important",
      "height:auto !important",
      "display:block !important",
      "visibility:visible !important",
      "opacity:1 !important",
      "pointer-events:auto !important",
      "background:transparent !important",
      "transform:none !important",
    ].join(";");
    el.attachShadow({ mode: "open" });
    (document.documentElement || document.body).appendChild(el);
    return el;
  }

  function render(matches) {
    const el = host();
    const root = el.shadowRoot;
    root.innerHTML = "";
    const wrap = document.createElement("div");
    wrap.style.cssText =
      "background:#1f2329;color:#fff;padding:10px 12px;border-radius:10px;font:13px/1.4 Segoe UI,sans-serif;box-shadow:0 8px 24px rgba(0,0,0,.25);";
    const title = document.createElement("div");
    title.textContent = matches.length > 1 ? `Sealbox · ${matches.length} 个匹配` : "Sealbox · 填充";
    title.style.marginBottom = "6px";
    wrap.appendChild(title);
    matches.slice(0, 8).forEach((m) => {
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
      b.style.cssText =
        "display:block;width:100%;margin:4px 0;padding:6px 8px;border:0;border-radius:6px;background:#5b5bd6;color:#fff;cursor:pointer;font:inherit;text-align:left;overflow:hidden;";
      b.addEventListener("click", (e) => {
        if (!e.isTrusted) return;
        chrome.runtime.sendMessage({ type: "fill-tab", id: m.id }, (res) => {
          if (res?.ok) remove();
          else {
            title.textContent = res?.error || "填充失败";
            title.style.color = "#fca5a5";
          }
        });
      });
      wrap.appendChild(b);
    });
    const close = document.createElement("button");
    close.type = "button";
    close.textContent = "关闭";
    close.style.cssText = "margin-top:4px;border:0;background:transparent;color:#aaa;cursor:pointer;font:inherit;";
    close.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      remove();
    });
    wrap.appendChild(close);
    root.appendChild(wrap);
  }

  if (!hasPasswordField()) return;

  chrome.storage.session.get(["overlayMatches"], (s) => {
    const matches = s.overlayMatches || [];
    if (!matches.length) {
      remove();
      return;
    }
    render(matches);
  });
})();
