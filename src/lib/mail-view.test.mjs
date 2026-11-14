import test from "node:test";
import assert from "node:assert/strict";
import {
  MAIL_FONT_SCALES,
  formatMailBadge,
  formatMailCacheStamp,
  formatMailFullTime,
  formatMailRelativeTime,
  isMailTypingTarget,
  mailFontScale,
  mailShortcutAction,
  nextMailFontScale,
  stepMailIndex,
} from "./mail-view.mjs";

// 2026-11-13 是周五；用它做「今天/昨天/7 天内」的基准。
const NOW = new Date(2026, 10, 13, 15, 30, 0);

test('相对时间：今天显示 HH:mm', () => {
  assert.equal(formatMailRelativeTime(new Date(2026, 10, 13, 9, 12, 0).toISOString(), NOW), "09:12");
  assert.equal(formatMailRelativeTime(new Date(2026, 10, 13, 0, 5, 0).toISOString(), NOW), "00:05");
});

test('相对时间：昨天显示「昨天」', () => {
  assert.equal(formatMailRelativeTime(new Date(2026, 10, 12, 23, 59, 0).toISOString(), NOW), "昨天");
  assert.equal(formatMailRelativeTime(new Date(2026, 10, 12, 0, 1, 0).toISOString(), NOW), "昨天");
});

test('相对时间：7 天内显示周X', () => {
  assert.equal(formatMailRelativeTime(new Date(2026, 10, 11, 10, 0, 0).toISOString(), NOW), "周三");
  assert.equal(formatMailRelativeTime(new Date(2026, 10, 8, 10, 0, 0).toISOString(), NOW), "周日");
  assert.equal(formatMailRelativeTime(new Date(2026, 10, 7, 10, 0, 0).toISOString(), NOW), "周六");
});

test('相对时间：更早显示 YYYY-MM-DD', () => {
  assert.equal(formatMailRelativeTime(new Date(2026, 10, 6, 10, 0, 0).toISOString(), NOW), "2026-11-06");
  assert.equal(formatMailRelativeTime("2020-01-02T03:04:00Z", NOW).startsWith("2020-01-0"), true);
});

test('相对时间：跨年不进周X，解析不了原样返回，畸形输入不抛', () => {
  const jan = new Date(2027, 0, 3, 10, 0, 0);
  assert.equal(formatMailRelativeTime(new Date(2026, 11, 30, 10, 0, 0).toISOString(), jan), "2026-12-30");
  assert.equal(formatMailRelativeTime("not-a-date", NOW), "not-a-date");
  assert.equal(formatMailRelativeTime("", NOW), "");
  assert.equal(formatMailRelativeTime(null, NOW), "");
  assert.equal(formatMailRelativeTime(undefined, NOW), "");
});

test('相对时间：RFC 822 日期能解析', () => {
  const raw = new Date(2026, 10, 13, 8, 7, 0).toString();
  assert.equal(formatMailRelativeTime(raw, NOW), "08:07");
});

test('完整时间与缓存时间戳', () => {
  assert.equal(formatMailFullTime(new Date(2026, 10, 12, 9, 12, 0).toISOString()), "2026-11-12 09:12");
  assert.equal(formatMailFullTime("garbage"), "garbage");
  assert.equal(formatMailCacheStamp(new Date(2026, 10, 13, 11, 5, 0).toISOString(), NOW), "11:05");
  assert.equal(formatMailCacheStamp(new Date(2026, 10, 12, 22, 40, 0).toISOString(), NOW), "昨天 22:40");
  assert.equal(formatMailCacheStamp("2026-11-01T08:00:00", NOW).endsWith("08:00"), true);
  assert.equal(formatMailCacheStamp("", NOW), "");
});

test('字号档位：未知值退回标准，三档循环', () => {
  assert.equal(MAIL_FONT_SCALES.length, 3);
  assert.equal(mailFontScale("large").px, 17);
  assert.equal(mailFontScale("no-such").id, "normal");
  assert.equal(mailFontScale(undefined).id, "normal");
  assert.equal(nextMailFontScale("small"), "normal");
  assert.equal(nextMailFontScale("normal"), "large");
  assert.equal(nextMailFontScale("large"), "small");
  assert.equal(nextMailFontScale("bogus"), "large");
});

test('角标：0 空串，超过 99 显示 99+', () => {
  assert.equal(formatMailBadge(0), "");
  assert.equal(formatMailBadge(-3), "");
  assert.equal(formatMailBadge(Number.NaN), "");
  assert.equal(formatMailBadge(7), "7");
  assert.equal(formatMailBadge(99), "99");
  assert.equal(formatMailBadge(100), "99+");
  assert.equal(formatMailBadge("12"), "12");
});

test('快捷键：j/k/Enter/u/Esc//r 映射，其余返回 null', () => {
  assert.equal(mailShortcutAction("j"), "next");
  assert.equal(mailShortcutAction("k"), "prev");
  assert.equal(mailShortcutAction("Enter"), "open");
  assert.equal(mailShortcutAction("u"), "back");
  assert.equal(mailShortcutAction("Escape"), "back");
  assert.equal(mailShortcutAction("/"), "focus-search");
  assert.equal(mailShortcutAction("r"), "refresh");
  assert.equal(mailShortcutAction("x"), null);
  assert.equal(mailShortcutAction(""), null);
  assert.equal(mailShortcutAction(null), null);
});

test('快捷键：带修饰键与组字中不触发', () => {
  assert.equal(mailShortcutAction("r", { ctrlKey: true }), null);
  assert.equal(mailShortcutAction("r", { metaKey: true }), null);
  assert.equal(mailShortcutAction("j", { altKey: true }), null);
  assert.equal(mailShortcutAction("j", { isComposing: true }), null);
});

test('输入区判定：input/textarea/select/contenteditable/iframe', () => {
  assert.equal(isMailTypingTarget({ tagName: "input" }), true);
  assert.equal(isMailTypingTarget({ tagName: "TEXTAREA" }), true);
  assert.equal(isMailTypingTarget({ tagName: "select" }), true);
  assert.equal(isMailTypingTarget({ tagName: "IFRAME" }), true);
  assert.equal(isMailTypingTarget({ tagName: "DIV", isContentEditable: true }), true);
  assert.equal(
    isMailTypingTarget({ tagName: "DIV", closest: (selector) => (selector === "[contenteditable]:not([contenteditable='false'])" ? {} : null) }),
    true,
  );
  assert.equal(isMailTypingTarget({ tagName: "DIV", isContentEditable: false, closest: () => null }), false);
  assert.equal(isMailTypingTarget({ tagName: "BUTTON" }), false);
});

test('输入区判定：null 与非对象不抛异常', () => {
  assert.equal(isMailTypingTarget(null), false);
  assert.equal(isMailTypingTarget(undefined), false);
  assert.equal(isMailTypingTarget("input"), false);
  assert.equal(isMailTypingTarget(42), false);
  assert.equal(
    isMailTypingTarget({
      tagName: "DIV",
      closest: () => {
        throw new Error("cross realm");
      },
    }),
    false,
  );
});

test('上下移动：空列表返回 -1，首次 j 选第一条，边界夹住不绕回', () => {
  assert.equal(stepMailIndex(-1, 1, 0), -1);
  assert.equal(stepMailIndex(-1, 1, 5), 0);
  assert.equal(stepMailIndex(-1, -1, 5), 4);
  assert.equal(stepMailIndex(0, 1, 5), 1);
  assert.equal(stepMailIndex(4, 1, 5), 4);
  assert.equal(stepMailIndex(0, -1, 5), 0);
  assert.equal(stepMailIndex(2, 1, 5), 3);
  assert.equal(stepMailIndex(Number.NaN, 1, 3), 0);
});
