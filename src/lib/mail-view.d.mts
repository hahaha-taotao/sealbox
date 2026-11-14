export interface MailFontScale {
  id: "small" | "normal" | "large";
  label: string;
  px: number;
  scale: number;
}

export const MAIL_FONT_SCALES: MailFontScale[];
export const MAIL_FONT_DEFAULT: "normal";
export function mailFontScale(id: string | null | undefined): MailFontScale;
export function nextMailFontScale(id: string | null | undefined): MailFontScale["id"];
export function formatMailRelativeTime(raw: string | number | Date | null | undefined, now?: Date): string;
export function formatMailFullTime(raw: string | number | Date | null | undefined): string;
export function formatMailCacheStamp(raw: string | number | Date | null | undefined, now?: Date): string;
export function formatMailBadge(count: number | string | null | undefined): string;
export function isMailTypingTarget(element: unknown): boolean;
export function mailShortcutAction(
  key: string | null | undefined,
  options?: { ctrlKey?: boolean; metaKey?: boolean; altKey?: boolean; isComposing?: boolean },
): "next" | "prev" | "open" | "back" | "focus-search" | "refresh" | null;
export function stepMailIndex(index: number, delta: number, length: number): number;
