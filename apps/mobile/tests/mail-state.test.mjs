import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';

// Exercise the actual mobile setup functions without a browser/Tauri runtime or build.
const source = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8');
const section = source.slice(source.indexOf('const MAIL_ROLES:'), source.indexOf('const DOMAIN ='));
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const flush = () => new Promise(resolve => setImmediate(resolve));
function setup(overrides = {}, confirm = () => true) {
  const context = vm.createContext({
    ref: value => ({ value }),
    computed: read => ({ get value() { return read(); } }),
    watch: () => {}, syncBackListener: () => {},
    page: { value: 'mail' }, showToast: () => {}, window: { confirm },
    MAIL_FONT_DEFAULT: 'normal', mailFontScale: () => ({ px: 15, scale: 1 }),
    formatMailCacheStamp: value => value, formatMailRelativeTime: value => value,
    formatMailFullTime: value => value, buildMailDocument: value => value,
    hasRemoteImages: () => false,
    normalizeMailList: payload => Array.isArray(payload)
      ? { messages: payload, cached: false, fetchedAt: null } : payload,
    api: {
      mailFolders: async () => [{ name: 'INBOX', role: 'inbox', unread: 2 }],
      mailList: async () => [], mailBody: async () => ({ text: 'body', html: null, truncated: false }),
      mailAttachments: async () => [], mailPrefetch: async () => 0,
      mailSetSeen: async () => {}, mailDelete: async () => {},
      ...overrides,
    },
  });
  const names = ['mailAccounts', 'mailAccountId', 'mailFolders', 'mailFilter', 'mailMessages',
    'mailMoreBusy', 'mailBusy', 'mailFoldersBusy', 'mailHasMore', 'mailBodyBusy', 'mailBodyText',
    'mailError', 'mailOpenMessage', 'mailAttachmentError', 'mailAttachmentsBusy', 'mailCacheLabel',
    'mailCacheCached', 'mailCacheAt', 'mailRoleUnread', 'loadMail', 'loadOlderMail',
    'selectMailAccount', 'chooseMailFilter', 'openMailMessage', 'closeMailMessage', 'stepMailMessage',
    'leaveMail', 'mutateMailMessage', 'mailMessageMutating', 'mailMutationError', 'mailEmpty',
    'mailRoleCounts'];
  const js = ts.transpileModule(`${section}\nglobalThis.subject = { ${names.join(',')} };`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
  }).outputText;
  vm.runInContext(js, context);
  const state = context.subject;
  state.mailAccountId.value = 'account-a';
  state.mailFolders.value = [{ name: 'INBOX', role: 'inbox', unread: 2 }];
  return state;
}
const message = uid => ({ uid, from: 'Sender <sender@example.com>', subject: 'Subject', seen: false });

test('body failure preserves unread state; attachments do not gate body success', async () => {
  const body = deferred();
  const attachments = deferred();
  const state = setup({ mailBody: () => body.promise, mailAttachments: () => attachments.promise });
  const row = message(1);
  state.mailMessages.value = [row];
  const pending = state.openMailMessage(row);
  assert.equal(row.seen, false);
  body.reject(new Error('body failed'));
  await pending;
  assert.equal(row.seen, false);
  assert.equal(state.mailFolders.value[0].unread, 2);
  assert.match(state.mailError.value, /body failed/);

  const success = setup({ mailAttachments: () => attachments.promise });
  const readable = message(2);
  success.mailMessages.value = [readable];
  await success.openMailMessage(readable);
  assert.equal(success.mailBodyBusy.value, false);
  assert.equal(success.mailBodyText.value, 'body');
  assert.equal(success.mailAttachmentsBusy.value, true);
  assert.equal(readable.seen, true);
  assert.equal(success.mailFolders.value[0].unread, 1);
  attachments.resolve([]);
  await flush();
});

test('rapid reader navigation ignores stale body and attachment results', async () => {
  const first = deferred();
  const attachments = deferred();
  const state = setup({ mailBody: (_id, uid) => uid === 1 ? first.promise : Promise.resolve({ text: 'second' }),
    mailAttachments: (_id, uid) => uid === 1 ? attachments.promise : Promise.resolve([]) });
  const a = message(1), b = message(2);
  state.mailMessages.value = [a, b];
  const pending = state.openMailMessage(a);
  state.stepMailMessage(1);
  await flush();
  first.resolve({ text: 'stale' });
  attachments.reject(new Error('stale attachments'));
  await pending;
  await flush();
  assert.equal(state.mailOpenMessage.value.uid, 2);
  assert.equal(state.mailBodyText.value, 'second');
  assert.equal(state.mailAttachmentError.value, '');
  assert.equal(state.mailAttachmentsBusy.value, false);
});

test('account switch resets pending pagination and discards previous-account folders', async () => {
  const older = deferred(), folders = deferred();
  let calls = 0;
  const state = setup({ mailList: () => ++calls === 1 ? older.promise : Promise.resolve([message(20)]),
    mailFolders: () => folders.promise });
  state.mailMessages.value = [message(10)];
  const pending = state.loadOlderMail();
  assert.equal(state.mailMoreBusy.value, true);
  const switching = state.selectMailAccount({ id: 'account-b', supported: true });
  assert.equal(state.mailMoreBusy.value, false);
  assert.equal(state.mailFolders.value.length, 0);
  state.chooseMailFilter('unread');
  assert.equal(state.mailFilter.value, 'all');
  folders.resolve([{ name: 'INBOX', role: 'inbox', unread: 9 }]);
  await switching;
  older.resolve([message(2)]);
  await pending;
  assert.equal(state.mailMoreBusy.value, false);
  assert.equal(state.mailBusy.value, false);
  assert.deepEqual(Array.from(state.mailMessages.value, row => row.uid), [20]);
  assert.equal(state.mailRoleUnread('inbox'), 9);
});

test('list filter races resolve to latest request and leaving invalidates pending work', async () => {
  const first = deferred(), second = deferred();
  let calls = 0;
  const state = setup({ mailList: () => ++calls === 1 ? first.promise : second.promise });
  const pending = state.loadMail();
  state.chooseMailFilter('unread');
  second.resolve([message(2)]);
  await flush();
  first.resolve([message(1)]);
  await pending;
  assert.deepEqual(Array.from(state.mailMessages.value, row => row.uid), [2]);
  assert.equal(state.mailBusy.value, false);
  state.leaveMail();
  assert.equal(state.mailMessages.value.length, 0);
  assert.equal(state.mailMoreBusy.value, false);
});

test('explicit toggle syncs server once and updates local unread counts only after success', async () => {
  const request = deferred();
  const calls = [];
  const state = setup({ mailSetSeen: (...args) => { calls.push(args); return request.promise; } });
  const row = message(1);
  state.mailMessages.value = [row];
  state.mailRoleCounts.value = { inbox: 5 };
  const pending = state.mutateMailMessage(row, 'seen');
  await state.mutateMailMessage(row, 'seen');
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], ['account-a', 1, true, 'INBOX']);
  assert.equal(row.seen, false);
  assert.equal(state.mailMessageMutating(row), true);
  request.resolve();
  await pending;
  assert.equal(row.seen, true);
  assert.equal(state.mailFolders.value[0].unread, 1);
  assert.equal(state.mailRoleCounts.value.inbox, 4);
  assert.equal(state.mailMessageMutating(row), false);
});

test('delete confirms, prevents duplicates and removes the active reader after success', async () => {
  const request = deferred();
  let calls = 0;
  const state = setup({ mailDelete: () => { calls++; return request.promise; } });
  const row = message(1);
  state.mailMessages.value = [row];
  state.mailOpenMessage.value = row;
  const pending = state.mutateMailMessage(row, 'delete');
  await state.mutateMailMessage(row, 'delete');
  assert.equal(calls, 1);
  assert.equal(state.mailOpenMessage.value.uid, 1);
  request.resolve();
  await pending;
  assert.equal(state.mailOpenMessage.value, null);
  assert.equal(state.mailMessages.value.length, 0);
  assert.equal(state.mailEmpty.value, true);
  assert.equal(state.mailFolders.value[0].unread, 1);
});

test('cancelled delete keeps mail and releases its busy reservation', async () => {
  let calls = 0, confirmations = 0;
  const state = setup({ mailDelete: async () => { calls++; } }, () => { confirmations++; return false; });
  const row = message(1);
  state.mailMessages.value = [row];
  await state.mutateMailMessage(row, 'delete');
  assert.equal(confirmations, 1);
  assert.equal(calls, 0);
  assert.equal(state.mailMessages.value.length, 1);
  assert.equal(state.mailMessageMutating(row), false);
});

test('mutation failures persist through reader close and never alter seen state', async () => {
  const state = setup({ mailSetSeen: async () => { throw new Error('server offline'); } });
  const row = message(1);
  state.mailMessages.value = [row];
  await state.mutateMailMessage(row, 'seen');
  assert.match(state.mailMutationError.value, /server offline/);
  state.closeMailMessage();
  assert.match(state.mailMutationError.value, /server offline/);
  assert.equal(row.seen, false);
  assert.equal(state.mailFolders.value[0].unread, 2);
});

test('old-account mutations retain own busy state without contaminating new account', async () => {
  const first = deferred(), second = deferred();
  const state = setup({ mailSetSeen: id => id === 'account-a' ? first.promise : second.promise });
  const old = message(1);
  state.mailMessages.value = [old];
  const pending = state.mutateMailMessage(old, 'seen');
  await state.selectMailAccount({ id: 'account-b', supported: true });
  const current = message(1);
  state.mailMessages.value = [current];
  const newer = state.mutateMailMessage(current, 'seen');
  first.reject(new Error('stale failure'));
  await pending;
  assert.equal(current.seen, false);
  assert.equal(state.mailMessageMutating(current), true);
  assert.equal(state.mailMutationError.value, '');
  second.resolve();
  await newer;
  assert.equal(current.seen, true);
});

test('stale successful delete does not remove the same UID from a new account', async () => {
  const request = deferred();
  const state = setup({ mailDelete: () => request.promise });
  const old = message(1);
  state.mailMessages.value = [old];
  const pending = state.mutateMailMessage(old, 'delete');
  await state.selectMailAccount({ id: 'account-b', supported: true });
  state.mailMessages.value = [message(1)];
  request.resolve();
  await pending;
  assert.equal(state.mailMessages.value.length, 1);
  assert.equal(state.mailFolders.value[0].unread, 2);
});

test('delete failure keeps reader and row, and stays separate from body errors', async () => {
  const state = setup({ mailDelete: async () => { throw new Error('delete failed'); } });
  const row = message(1);
  state.mailMessages.value = [row];
  state.mailOpenMessage.value = row;
  await state.mutateMailMessage(row, 'delete');
  assert.equal(state.mailMessages.value.length, 1);
  assert.equal(state.mailOpenMessage.value.uid, 1);
  assert.equal(state.mailError.value, '');
  assert.match(state.mailMutationError.value, /delete failed/);
  await state.openMailMessage(message(2));
  assert.equal(state.mailMutationError.value, '');
});

test('delete completion for an earlier reader keeps the newer reader open', async () => {
  const request = deferred();
  const state = setup({ mailDelete: () => request.promise });
  const first = message(1), second = message(2);
  state.mailMessages.value = [first, second];
  state.mailOpenMessage.value = first;
  const pending = state.mutateMailMessage(first, 'delete');
  await state.openMailMessage(second);
  request.resolve();
  await pending;
  assert.equal(state.mailOpenMessage.value.uid, 2);
  assert.deepEqual(Array.from(state.mailMessages.value, row => row.uid), [2]);
});

test('an older body response does not undo explicit mark-unread', async () => {
  const body = deferred();
  const state = setup({ mailBody: () => body.promise });
  const row = { ...message(1), seen: true };
  state.mailMessages.value = [row];
  const reading = state.openMailMessage(row);
  await state.mutateMailMessage(row, 'seen');
  body.resolve({ text: 'body' });
  await reading;
  assert.equal(row.seen, false);
  assert.equal(state.mailFolders.value[0].unread, 3);
});

test('cache label describes provenance, not network status', () => {
  const state = setup();
  state.mailCacheCached.value = true;
  state.mailCacheAt.value = '10:00';
  assert.equal(state.mailCacheLabel.value, '本地缓存 · 更新于 10:00');
});
