import test from 'node:test';
import assert from 'node:assert/strict';
import { createAuditRequestGuard, auditDateBounds } from './audit-request.ts';

test('locking invalidates pending audit results, including after unlocking', async () => {
  const guard = createAuditRequestGuard();
  let complete;
  const pending = new Promise(resolve => { complete = resolve; });
  const id = guard.begin();
  let rows = [];
  const task = pending.then(value => { if (guard.isCurrent(id)) rows = value; });
  guard.invalidate();
  guard.begin();
  complete(['private audit']);
  await task;
  assert.deepEqual(rows, []);
});
test('only latest query may update items, error and loading state', () => {
  const guard = createAuditRequestGuard();
  const first = guard.begin();
  const latest = guard.begin();
  assert.equal(guard.isCurrent(first), false);
  assert.equal(guard.isCurrent(latest), true);
});
test('date bounds include the selected final local day', () => {
  const bounds = auditDateBounds('2026-10-20', '2026-10-23');
  assert.equal(new Date(bounds.from).getDate(), 20);
  assert.equal(new Date(bounds.to).getDate(), 24);
  assert.throws(() => auditDateBounds('2026-10-24', '2026-10-23'));
  assert.deepEqual(auditDateBounds('', ''), { from: null, to: null });
});
