import { test } from 'node:test';
import assert from 'node:assert/strict';
import { login, verify } from '../src/auth.js';

// These run against the default dev password ('admin') when no env is set.

test('login issues a valid token for the correct password', () => {
  const token = login('admin');
  assert.ok(token, 'expected a token to be issued');
  assert.equal(verify(token), true);
});

test('login rejects a wrong password', () => {
  assert.equal(login('wrong'), null);
});

test('verify rejects tampered or malformed tokens', () => {
  const token = login('admin');
  assert.equal(verify(token + 'x'), false);
  assert.equal(verify('not-a-token'), false);
  assert.equal(verify(''), false);
  assert.equal(verify(null), false);
});
