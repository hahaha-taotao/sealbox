import test from 'node:test';
import assert from 'node:assert/strict';
import { mailMessageKey, mergeMailInbox } from './mail-inbox.mjs';
const mail = (entryId, uid, date, folder = 'INBOX') => ({ entryId, uid, date, folder });
test('UID collisions retain account and folder identity', () => {
  const rows = [mail('a', 1, '2026-11-15'), mail('b', 1, '2026-11-15'), mail('a', 1, '2026-11-15', 'Archive')];
  assert.equal(new Set(rows.map(mailMessageKey)).size, 3);
  assert.equal(mergeMailInbox(rows).length, 3);
});
test('unified inbox sorts by date rather than account UID', () => {
  const rows = mergeMailInbox([mail('a', 999, '2026-11-13'), mail('b', 1, '2026-11-15'), mail('a', 1000, 'invalid')]);
  assert.deepEqual(rows.map(row => row.uid), [1, 999, 1000]);
});
test('pagination merges duplicate messages and replaces stale metadata', () => {
  const row = mail('a', 1, '2026-11-15');
  assert.deepEqual(mergeMailInbox([row, { ...row, seen: true }]), [{ ...row, seen: true }]);
});
test('same-time ordering is stable and malformed dates stay last', () => {
  const rows = [mail('b', 2, 'invalid'), mail('b', 1, '2026-11-15'), mail('a', 1, '2026-11-15'), mail('a', 2, '')];
  assert.deepEqual(mergeMailInbox(rows), mergeMailInbox([...rows].reverse()));
  assert.deepEqual(mergeMailInbox([]), []);
});
