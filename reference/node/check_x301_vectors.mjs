#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as x from './x301.mjs';

const root = new URL('../../', import.meta.url);
const corpus = JSON.parse(readFileSync(new URL('vectors/x301-v2.json', root)));
const contract = readFileSync(new URL('phase-b/inputs/X301-v2_EINGABEVERTRAG_2026-09-10.md', root));
assert.equal(createHash('sha256').update(contract).digest('hex'), corpus.contract_sha256);
assert.equal(corpus.parameter_sha256, x.parameterHash);
const hex = s => Buffer.from(s, 'hex');
const keys = new Map(corpus.keys.map(k => [k.id, k]));

for (const key of corpus.keys) {
  const secret = hex(key.secret_hex), original = Buffer.from(secret);
  assert.equal(x.clamp(secret).toString('hex'), key.clamped_hex, key.id);
  assert.deepEqual(x.importSecret(secret), original, key.id);
  assert.equal(x.publicKey(secret).toString('hex'), key.public_hex, key.id);
  assert.equal(x.diagnostics.rounds, 301);
  assert.deepEqual(secret, original);
}
for (const pair of corpus.dh) {
  const a = keys.get(pair.a), b = keys.get(pair.b);
  assert.equal(x.shared(hex(a.secret_hex), hex(b.public_hex)).toString('hex'), pair.shared_hex, pair.id);
  assert.equal(x.shared(hex(b.secret_hex), hex(a.public_hex)).toString('hex'), pair.shared_hex, pair.id);
}
for (const v of corpus.evaluations) {
  const result = x.x301(hex(keys.get(v.key).secret_hex), hex(v.u_hex));
  assert.equal(result.toString('hex'), v.result_hex, v.id);
  assert.deepEqual(x.encode(x.decode(result)), result);
  assert.equal(x.diagnostics.rounds, 301);
}
for (const v of corpus.errors) {
  const calls = x.diagnostics.ladderCalls;
  const sentinel = Symbol('no output');
  let output = sentinel;
  assert.throws(() => { output = x.x301(hex(v.secret_hex), hex(v.u_hex)); },
    v.stage === 'result' ? x.AllZeroError : RangeError, v.id);
  assert.equal(output, sentinel, v.id);
  assert.equal(x.diagnostics.ladderCalls - calls, v.stage === 'result' ? 1 : 0, v.id);
}
assert.equal(new Set(corpus.weak_secrets.map(v => v.secret_hex)).size, 64);
for (const v of corpus.weak_secrets) {
  const secret = hex(v.secret_hex), copy = Buffer.from(secret), calls = x.diagnostics.ladderCalls;
  assert.throws(() => x.clamp(secret), x.WeakSecretError, v.id);
  assert.throws(() => x.importSecret(secret), x.WeakSecretError, v.id);
  assert.throws(() => x.publicKey(secret), x.WeakSecretError, v.id);
  assert.throws(() => x.shared(secret, x.base), x.WeakSecretError, v.id);
  assert.equal(x.diagnostics.ladderCalls, calls, v.id);
  assert.deepEqual(secret, copy);
  let draws = 0;
  const generated = x.keygen(size => {
    assert.equal(size, 38);
    return ++draws === 1 ? secret : Buffer.alloc(38);
  });
  assert.equal(draws, 2, v.id);
  assert.deepEqual(generated[0], Buffer.alloc(38));
  assert.equal(generated[1].toString('hex'), keys.get('zeros').public_hex);
}
for (const bad of [Buffer.alloc(37), Buffer.alloc(39), null, 'not bytes']) {
  let draws = 0;
  assert.throws(() => x.keygen(() => { draws++; return bad; }), RangeError);
  assert.equal(draws, 1);
}
const rngError = new Error('test RNG failure');
assert.throws(() => x.keygen(() => { throw rngError; }), e => e === rngError);
assert.throws(() => x.finalize([0n, 1n]), x.AllZeroError);
assert.throws(() => x.finalize([1n, 0n]), x.AllZeroError);
for (const scalar of [0n, 1n, 1n << 300n, (1n << 301n) - 4n]) {
  x.ladder(scalar, x.decode(x.base));
  assert.equal(x.diagnostics.rounds, 301);
}
let k = x.base, u = x.base;
const checkpoints = new Map(corpus.iteration.checkpoints.map(v => [v.count, v]));
assert.deepEqual([...checkpoints.keys()], [1, 10, 100, 1000]);
for (let i = 1; i <= 1000; i++) {
  [k, u] = [x.x301(k, u), k];
  if (checkpoints.has(i)) {
    assert.equal(k.toString('hex'), checkpoints.get(i).k_hex, `iteration ${i}: k`);
    assert.equal(u.toString('hex'), checkpoints.get(i).u_hex, `iteration ${i}: u`);
  }
}
console.log(JSON.stringify({ status: 'PASS', oracle: 'Node independent X301 add/double ladder',
  keys: corpus.keys.length, dh_pairs: corpus.dh.length, evaluations: corpus.evaluations.length,
  rejected_inputs: corpus.errors.length, weak_secret_aliases: corpus.weak_secrets.length,
  weak_alias_entrypoints: ['clamp', 'import', 'public', 'shared', 'keygen-resample'],
  pre_ladder_rejection_checked: true, iteration_checkpoints: [...checkpoints.keys()] }));
