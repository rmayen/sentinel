import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPrivateAddress, assertSafeUrl } from '../src/ssrf.js';

test('isPrivateAddress blocks private, loopback, and reserved IPv4', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255',
    '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1']) {
    assert.equal(isPrivateAddress(ip), true, `${ip} should be blocked`);
  }
});

test('isPrivateAddress allows public IPv4', () => {
  for (const ip of ['8.8.8.8', '93.184.216.34', '1.1.1.1', '172.15.0.1', '172.32.0.1']) {
    assert.equal(isPrivateAddress(ip), false, `${ip} should be allowed`);
  }
});

test('isPrivateAddress handles IPv6', () => {
  assert.equal(isPrivateAddress('::1'), true);
  assert.equal(isPrivateAddress('fe80::1'), true);
  assert.equal(isPrivateAddress('fc00::1'), true);
  assert.equal(isPrivateAddress('::ffff:127.0.0.1'), true); // mapped loopback
  assert.equal(isPrivateAddress('2606:4700:4700::1111'), false); // public
});

test('assertSafeUrl rejects non-http schemes and private literals', async () => {
  await assert.rejects(assertSafeUrl('file:///etc/passwd'), /http/);
  await assert.rejects(assertSafeUrl('http://127.0.0.1/'), /private or reserved/);
  await assert.rejects(assertSafeUrl('http://169.254.169.254/latest/meta-data/'), /private or reserved/);
  await assert.rejects(assertSafeUrl('not a url'), /invalid url/);
});

test('assertSafeUrl accepts a public IP literal', async () => {
  await assert.doesNotReject(assertSafeUrl('http://93.184.216.34/'));
});
