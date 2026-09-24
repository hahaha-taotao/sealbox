(function (root) {
  function isRendered(el) {
    if (!el) return false;
    const st = getComputedStyle(el);
    if (st.display === "none" || st.visibility === "hidden") return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  }

  function collectInputs(root, acc) {
    if (!root) return acc;
    const list = root.querySelectorAll ? root.querySelectorAll("input, textarea") : [];
    for (const el of list) acc.push(el);
    const all = root.querySelectorAll ? root.querySelectorAll("*") : [];
    for (const el of all) {
      if (el.shadowRoot) collectInputs(el.shadowRoot, acc);
    }
    return acc;
  }

  function attrs(el) {
    return `${el.type || ""} ${el.name || ""} ${el.id || ""} ${el.className || ""} ${el.placeholder || ""} ${el.autocomplete || ""} ${el.getAttribute("aria-label") || ""}`;
  }

  function isPasswordField(el) {
    if (!(el instanceof HTMLInputElement) && !(el instanceof HTMLTextAreaElement)) return false;
    const type = String(el.type || "").toLowerCase();
    if (type === "password") return true;
    const a = attrs(el);
    return /password|passwd|pwd|secret|密码|口令|通行/i.test(a);
  }

  function isUsernameField(el, password) {
    if (el === password) return false;
    if (!(el instanceof HTMLInputElement)) return false;
    const type = String(el.type || "").toLowerCase();
    if (type === "hidden" || type === "submit" || type === "button" || type === "checkbox" || type === "radio" || type === "file") {
      return false;
    }
    if (el.readOnly || el.disabled) return false;
    if (type === "email" || type === "tel") return true;
    const a = attrs(el);
    if (/user|login|email|account|phone|mobile|账号|用户|工号|手机/i.test(a)) return true;
    return type === "text" || type === "number" || !type;
  }

  function rank(el) {
    let n = 0;
    if (isRendered(el)) n += 10;
    if (!el.disabled) n += 2;
    if (!el.readOnly) n += 2;
    return n;
  }

  function nativeValue(el) {
    if (!el) return "";
    const Fill = root.SealboxFill || globalThis.SealboxFill;
    if (Fill?.nativeValue) return Fill.nativeValue(el);
    let proto = Object.getPrototypeOf(el);
    while (proto && proto !== Object.prototype) {
      const desc = Object.getOwnPropertyDescriptor(proto, "value");
      if (desc?.get) {
        try {
          const v = desc.get.call(el);
          if (v != null && String(v) !== "") return String(v);
        } catch (_) {
          /* ignore */
        }
      }
      proto = Object.getPrototypeOf(proto);
    }
    return String(el.value || "");
  }

  function snapshot(el) {
    let rendered = false;
    let hidden = String(el.type || "").toLowerCase() === "hidden";
    try {
      const st = getComputedStyle(el);
      const r = el.getBoundingClientRect();
      rendered = r.width > 0 && r.height > 0;
      hidden =
        hidden ||
        st.display === "none" ||
        st.visibility === "hidden" ||
        Number(st.opacity) === 0;
    } catch (_) {
      /* detached */
    }
    return {
      type: el.type || "",
      name: el.name || "",
      id: el.id || "",
      placeholder: el.placeholder || "",
      autocomplete: el.autocomplete || "",
      maxlength: el.getAttribute?.("maxlength") || el.maxLength || "",
      className: String(el.className || ""),
      ariaLabel: el.getAttribute?.("aria-label") || "",
      label: (() => {
        const labels = el.labels ? Array.from(el.labels).map((label) => label.textContent || "").join(" ") : "";
        return labels || el.closest?.("label")?.textContent || "";
      })(),
      value: nativeValue(el),
      hidden,
      rendered,
      disabled: Boolean(el.disabled),
      readOnly: Boolean(el.readOnly),
      textSecurity: (() => {
        try {
          const st = getComputedStyle(el);
          return st.webkitTextSecurity || st.textSecurity || "";
        } catch (_) {
          return "";
        }
      })(),
    };
  }

  function findFields(rootEl) {
    const root = rootEl || document;
    const inputs = collectInputs(root, []);
    const Fill = root.SealboxFill || globalThis.SealboxFill;
    if (Fill?.pickLoginValues) {
      const picked = Fill.pickLoginValues(inputs.map(snapshot));
      if (!picked?.hasPassword || picked.passwordIndex < 0) return null;
      const password = inputs[picked.passwordIndex];
      const user = picked.usernameIndex >= 0 ? inputs[picked.usernameIndex] : null;
      return { user, password, form: password?.form || null };
    }
    const passwords = inputs.filter(isPasswordField).sort((a, b) => rank(b) - rank(a));
    if (!passwords.length) return null;
    const password = passwords[0];
    const form = password.form;
    const scopeInputs = form ? collectInputs(form, []) : inputs;
    const users = scopeInputs.filter((el) => isUsernameField(el, password)).sort((a, b) => rank(b) - rank(a));
    return { user: users[0] || null, password, form };
  }

  function setValue(el, value) {
    if (!el) return;
    const wasReadOnly = el.readOnly;
    const wasDisabled = el.disabled;
    try {
      el.readOnly = false;
      el.disabled = false;
      el.focus();
      const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
      setter ? setter.call(el, value) : (el.value = value);
      el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, data: value }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      el.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));
    } finally {
      el.readOnly = wasReadOnly;
      el.disabled = wasDisabled;
    }
  }

  function findOtpField(rootEl) {
    const Fill = root.SealboxFill || globalThis.SealboxFill;
    if (!Fill?.isOtpField) return null;
    return collectInputs(rootEl || document, []).find((el) => {
      const info = snapshot(el);
      return info.rendered && !info.hidden && !info.disabled && !info.readOnly && Fill.isOtpField(info);
    }) || null;
  }

  function fill(username, password, totp) {
    const fields = findFields(document);
    if (!fields?.password) return { ok: false, error: "no-password-field", filledTotp: false };
    setValue(fields.user, username || "");
    setValue(fields.password, password || "");
    const otpField = totp ? findOtpField(document) : null;
    if (otpField) setValue(otpField, totp);
    return { ok: true, filledTotp: Boolean(otpField) };
  }

  function readFields() {
    const inputs = collectInputs(document, []);
    const Fill = root.SealboxFill || globalThis.SealboxFill;
    if (Fill?.pickLoginValues) {
      const picked = Fill.pickLoginValues(inputs.map(snapshot));
      return {
        ok: true,
        username: picked.username || "",
        password: picked.password || "",
        hasPassword: Boolean(picked.hasPassword),
      };
    }
    const fields = findFields(document);
    return {
      ok: true,
      username: nativeValue(fields?.user),
      password: nativeValue(fields?.password),
      hasPassword: Boolean(fields?.password),
    };
  }

  root.SealboxPageFill = { findFields, findOtpField, setValue, fill, readFields };
})(typeof globalThis !== "undefined" ? globalThis : this);
