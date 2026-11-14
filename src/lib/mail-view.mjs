/**
 * 邮箱界面的纯函数：相对时间、正文字号档位、快捷键焦点守卫。
 *
 * 放在 .mjs 里而不是 .ts，是因为 vue-tsc 不检查 .mjs，node --test 又能直接跑；
 * 桌面 App.vue 与 apps/mobile 都 import 同一份实现，保证两端显示一致。
 * 这些函数不碰 DOM、不发请求，输入畸形也不抛异常。
 */

/** 正文字号三档；`scale` 是 iframe 的 zoom，`px` 是纯文本视图的字号。 */
export const MAIL_FONT_SCALES = [
  { id: "small", label: "小", px: 13, scale: 0.9 },
  { id: "normal", label: "标准", px: 15, scale: 1 },
  { id: "large", label: "大", px: 17, scale: 1.2 },
];

export const MAIL_FONT_DEFAULT = "normal";

/** 未知档位一律退回「标准」，避免旧的本地偏好把界面锁在小字号。 */
export function mailFontScale(id) {
  return MAIL_FONT_SCALES.find((entry) => entry.id === id) ?? MAIL_FONT_SCALES[1];
}

/** 三档循环：小 → 标准 → 大 → 小。 */
export function nextMailFontScale(id) {
  const index = MAIL_FONT_SCALES.findIndex((entry) => entry.id === mailFontScale(id).id);
  return MAIL_FONT_SCALES[(index + 1) % MAIL_FONT_SCALES.length].id;
}

const MAIL_WEEKDAYS = ["周日", "周一", "周二", "周三", "周四", "周五", "周六"];

/** 补零；负数和 NaN 都当 0 处理。 */
function pad2(value) {
  const n = Number.isFinite(value) ? Math.trunc(value) : 0;
  return String(n < 0 ? 0 : n).padStart(2, "0");
}

/** 两个时间之间相差几个自然日（按本地日历，不用毫秒除，避开夏令时）。 */
function calendarDaysApart(from, to) {
  const a = new Date(from.getFullYear(), from.getMonth(), from.getDate());
  const b = new Date(to.getFullYear(), to.getMonth(), to.getDate());
  return Math.round((b.getTime() - a.getTime()) / 86400000);
}

function toDate(value) {
  if (value instanceof Date) return value;
  if (typeof value === "number") return new Date(value);
  if (typeof value !== "string") return null;
  const raw = value.trim();
  if (raw === "") return null;
  const parsed = new Date(raw);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

/**
 * 列表行的时间列：
 * - 今天 → `HH:mm`
 * - 昨天 → `昨天`
 * - 同一自然年内 7 天内（含未来时间）→ `周X`
 * - 其余 → `YYYY-MM-DD`
 * 解析不了的原样返回，方便排查服务器日期格式。
 */
export function formatMailRelativeTime(raw, now = new Date()) {
  const date = toDate(raw);
  if (date === null) return typeof raw === "string" ? raw : "";
  const base = toDate(now) ?? new Date();
  const days = calendarDaysApart(base, date);
  if (days === 0) return `${pad2(date.getHours())}:${pad2(date.getMinutes())}`;
  if (days === -1) return "昨天";
  // 未来时间（发件端时钟快）落进 7 天窗口时也显示周X，不写「明天」。
  if (days <= 6 && days >= -6 && date.getFullYear() === base.getFullYear()) {
    return MAIL_WEEKDAYS[date.getDay()] ?? "";
  }
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}`;
}

/** 正文工具栏里的完整时间：`2026-11-12 09:12`。 */
export function formatMailFullTime(raw) {
  const date = toDate(raw);
  if (date === null) return typeof raw === "string" ? raw : "";
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())} ${pad2(date.getHours())}:${pad2(date.getMinutes())}`;
}

/**
 * 缓存态提示的更新时间：只给 `HH:mm`，跨天时补上日期，免得把昨天的缓存说成今天。
 */
export function formatMailCacheStamp(raw, now = new Date()) {
  const date = toDate(raw);
  if (date === null) return "";
  const base = toDate(now) ?? new Date();
  const clock = `${pad2(date.getHours())}:${pad2(date.getMinutes())}`;
  const days = calendarDaysApart(base, date);
  if (days === 0) return clock;
  if (days === -1) return `昨天 ${clock}`;
  return `${pad2(date.getMonth() + 1)}-${pad2(date.getDate())} ${clock}`;
}

/** 未读角标最多显示 99+，0 返回空串（调用方据此不渲染角标）。 */
export function formatMailBadge(count) {
  const n = Number(count);
  if (!Number.isFinite(n) || n <= 0) return "";
  return n > 99 ? "99+" : String(Math.trunc(n));
}

const MAIL_INPUT_TAGS = new Set(["INPUT", "TEXTAREA", "SELECT"]);

/**
 * 判断一个 focus 目标是不是可输入区域。键盘快捷键只在返回 false 时生效，
 * 这样在搜索框里打 j/k 不会翻邮件。iframe 单独判断：焦点进了正文就不抢键。
 * 传入的可能是事件目标、document.activeElement，也可能什么都不是，对畸形输入返回 false。
 */
export function isMailTypingTarget(element) {
  if (element === null || element === undefined) return false;
  if (typeof element !== "object") return false;
  const tagName = typeof element.tagName === "string" ? element.tagName.toUpperCase() : "";
  if (MAIL_INPUT_TAGS.has(tagName)) return true;
  if (tagName === "IFRAME" || tagName === "FRAME") return true;
  if (element.isContentEditable === true) return true;
  if (typeof element.closest === "function") {
    try {
      if (element.closest("[contenteditable]:not([contenteditable='false'])") !== null) return true;
    } catch {
      // 跨 realm 的 Element 在个别 WebView 里 closest 会抛，按非输入区处理。
    }
  }
  return false;
}

/**
 * 解析键盘事件为邮箱快捷键动作；返回 null 表示不归邮箱管。
 * 带修饰键、输入法组字中的事件一律不处理。
 */
export function mailShortcutAction(key, options = {}) {
  if (typeof key !== "string" || key === "") return null;
  if (options.ctrlKey || options.metaKey || options.altKey) return null;
  if (options.isComposing === true) return null;
  switch (key) {
    case "j":
      return "next";
    case "k":
      return "prev";
    case "Enter":
      return "open";
    case "u":
    case "Escape":
      return "back";
    case "/":
      return "focus-search";
    case "r":
      return "refresh";
    default:
      return null;
  }
}

/** 上下移动后的新下标：列表为空返回 -1，越界时夹在两端而不是绕回。 */
export function stepMailIndex(index, delta, length) {
  const total = Number.isFinite(length) ? Math.trunc(length) : 0;
  if (total <= 0) return -1;
  const current = Number.isFinite(index) ? Math.trunc(index) : -1;
  if (current < 0) return delta > 0 ? 0 : total - 1;
  const next = current + (Number.isFinite(delta) ? Math.trunc(delta) : 0);
  if (next < 0) return 0;
  if (next > total - 1) return total - 1;
  return next;
}
