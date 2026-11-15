/** IMAP UID 只在同一账号、文件夹中唯一，统一收件箱必须保留完整来源。 */
export function mailMessageKey(message) {
  return JSON.stringify([message.entryId ?? "", message.folder ?? "INBOX", message.uid]);
}

/** 跨账号按邮件时间排序；无效日期放最后，同时间以来源键稳定排序。 */
export function mergeMailInbox(messages) {
  const unique = new Map(messages.map((message) => [mailMessageKey(message), message]));
  const stamp = (value) => {
    const time = Date.parse(value);
    return Number.isFinite(time) ? time : -Infinity;
  };
  return [...unique.values()].sort((a, b) => {
    const left = stamp(a.date);
    const right = stamp(b.date);
    return (left === right ? 0 : left > right ? -1 : 1)
      || mailMessageKey(a).localeCompare(mailMessageKey(b));
  });
}
