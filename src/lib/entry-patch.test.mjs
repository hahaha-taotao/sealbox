import test from 'node:test';
import assert from 'node:assert/strict';
import { presencePatch, preservePayload, storedOption } from './entry-patch.mjs';
test('hidden mailbox/SSH/expiry fields are not cleared', () => {
  const baseline = { expires_at: '2030-01-01', imap_host: 'imap.test', imap_port: 993, smtp_host: 'smtp.test', smtp_port: 465, key_type: 'rsa', public_fingerprint: 'public', password: 'before' };
  assert.deepEqual(preservePayload(baseline, { password: 'after', imap_host: null }, ['password']), { ...baseline, password: 'after' });
  assert.deepEqual(presencePatch(baseline, { expires_at: null }), { expires_at: null });
  assert.deepEqual(presencePatch(baseline, { password: undefined }), {});
});
test('unknown protocol/engine survive edits and remain selectable', () => {
  assert.equal(preservePayload({ protocol: 'telnet' }, { host: 'new' }).protocol, 'telnet');
  assert.equal(preservePayload({ engine: 'futuredb' }, { username: 'new' }).engine, 'futuredb');
  assert.deepEqual(storedOption(['ssh'], 'telnet'), ['ssh', 'telnet']);
});
