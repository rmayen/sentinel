import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAuth } from '../src/auth.js';

const auth = createAuth({ password: 'test-pass', secret: 'test-secret' });

test('createAuth requires a password', () => {
  assert.throws(() => createAuth({}), /password is required/);
});

test('login issues a valid token for the correct password', () => {
  const token = auth.login('test-pass');
  assert.ok(token, 'expected a token to be issued');
  assert.equal(auth.verify(token), true);
});

test('login rejects a wrong password', () => {
  assert.equal(auth.login('wrong'), null);
});

test('verify rejects tampered or malformed tokens', () => {
  const token = auth.login('test-pass');
  assert.equal(auth.verify(token + 'x'), false);
  assert.equal(auth.verify('not-a-token'), false);
  assert.equal(auth.verify(''), false);
  assert.equal(auth.verify(null), false);
});

test('a token signed with a different secret does not verify', () => {
  const other = createAuth({ password: 'test-pass', secret: 'different-secret' });
  const token = other.login('test-pass');
  assert.equal(auth.verify(token), false);
});
