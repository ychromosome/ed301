#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Independent-language test oracle, NOT FOR PRODUCTION or constant-time use.
// Uses generic extended Edwards coordinates (EFD add-2008-hwcd), unlike the
// Python affine reference. No Python implementation or generated constants are
// imported: curve parameters come directly from the immutable Gate-A package.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const root = new URL('../../', import.meta.url);
const parameterBytes = readFileSync(new URL('provenance/phase-a/2026-09-09/parameter/ed301-v2.json', root));
const parameterHash = '13f0eaf541919a1447b9d3c58e6d57eb77ffab94ebe37539c70301d6fddcfaa0';
assert.equal(createHash('sha256').update(parameterBytes).digest('hex'), parameterHash);
const parameter = JSON.parse(parameterBytes);
const p = BigInt(parameter.field.p_decimal);
const a = BigInt(parameter.edwards.a_decimal);
const d = BigInt(parameter.edwards.d_decimal);
const q = BigInt(parameter.group.q_decimal);
const cofactor = BigInt(parameter.group.cofactor_h);
const width = parameter.encoding.field_bytes;
const mod = x => ((x % p) + p) % p;
const identity = [0n, 1n, 1n, 0n]; // X,Y,Z,T; XY = ZT.
const gx = BigInt(parameter.basepoint.G_edwards_x_decimal);
const gy = BigInt(parameter.basepoint.G_edwards_y_decimal);
const base = [gx, gy, 1n, mod(gx * gy)];

function power(x, exponent) {
  let y = 1n;
  x = mod(x);
  for (const bit of exponent.toString(2)) {
    y = mod(y * y);
    if (bit === '1') y = mod(y * x);
  }
  return y;
}

function inverse(x) {
  if (mod(x) === 0n) throw new RangeError('inverse of zero');
  return power(x, p - 2n);
}

function add([x1, y1, z1, t1], [x2, y2, z2, t2]) {
  // https://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
  const aa = mod(x1 * x2), bb = mod(y1 * y2);
  const cc = mod(d * t1 * t2), dd = mod(z1 * z2);
  const ee = mod((x1 + y1) * (x2 + y2) - aa - bb);
  const ff = mod(dd - cc), gg = mod(dd + cc), hh = mod(bb - a * aa);
  const result = [mod(ee * ff), mod(gg * hh), mod(ff * gg), mod(ee * hh)];
  if (result[2] === 0n || mod(result[0] * result[1] - result[2] * result[3]) !== 0n)
    throw new Error('extended-coordinate invariant');
  return result;
}

function multiply(n, point) {
  if (n < 0n) return multiply(-n, [mod(-point[0]), point[1], point[2], mod(-point[3])]);
  let result = identity;
  for (const bit of n.toString(2)) {
    result = add(result, result);
    if (bit === '1') result = add(result, point);
  }
  return result;
}

function equal(left, right) {
  return mod(left[0] * right[2] - right[0] * left[2]) === 0n &&
    mod(left[1] * right[2] - right[1] * left[2]) === 0n;
}

function little(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

function encodeInteger(n) {
  if (n < 0n || n >= 1n << BigInt(8 * width)) throw new RangeError('integer width');
  const out = Buffer.alloc(width);
  for (let i = 0; i < width; i++, n >>= 8n) out[i] = Number(n & 255n);
  return out;
}

function encode(point) {
  const iz = inverse(point[2]);
  const x = mod(point[0] * iz), y = mod(point[1] * iz);
  const bytes = encodeInteger(y);
  bytes[width - 1] |= Number(x & 1n) << 7;
  return bytes;
}

function decode(bytes, publicKey = false) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== width || (bytes[width - 1] & 0x60))
    throw new RangeError('point format');
  const sign = BigInt(bytes[width - 1] >> 7);
  const y = little(bytes) & ((1n << 301n) - 1n);
  if (y >= p) throw new RangeError('noncanonical y');
  const xx = mod((1n - y * y) * inverse(a - d * y * y));
  let x = power(xx, (p + 1n) / 4n);
  if (mod(x * x) !== xx || (x === 0n && sign === 1n)) throw new RangeError('non-point or negative zero');
  if ((x & 1n) !== sign) x = p - x;
  const point = [x, y, 1n, mod(x * y)];
  if (publicKey && (equal(point, identity) || !equal(multiply(q, point), identity)))
    throw new RangeError('public-key subgroup');
  return point;
}

function decodeScalar(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== width) throw new RangeError('scalar length');
  const n = little(bytes);
  if (n >= q) throw new RangeError('noncanonical scalar');
  return n;
}

function domain(context) {
  if (!Buffer.isBuffer(context) || context.length > 255) throw new RangeError('context');
  return Buffer.concat([Buffer.from('SigEd301-v2', 'ascii'), Buffer.from([0, context.length]), context]);
}

function shake(...parts) {
  const hash = createHash('shake256', { outputLength: 2 * width });
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function trace(seed, message, context, nonceDomain = domain(context), challengeDomain = domain(context)) {
  if (!Buffer.isBuffer(seed) || seed.length !== width || !Buffer.isBuffer(message)) throw new RangeError('signing input');
  const expanded = shake(seed);
  const lower = Buffer.from(expanded.subarray(0, width));
  lower[0] &= 252;
  lower[width - 1] = (lower[width - 1] & 15) | 16;
  const s = little(lower), prefix = expanded.subarray(width);
  const publicKey = encode(multiply(s, base));
  const nonceHash = shake(nonceDomain, prefix, message), r = little(nonceHash) % q;
  const commitment = encode(multiply(r, base));
  const challengeHash = shake(challengeDomain, commitment, publicKey, message), k = little(challengeHash) % q;
  const response = encodeInteger((r + k * s) % q);
  return { domain: nonceDomain, expanded_hash: expanded, pruned_secret_scalar: lower,
    prefix, public_key: publicKey, nonce_hash: nonceHash, nonce_scalar: encodeInteger(r), commitment,
    challenge_hash: challengeHash, challenge_scalar: encodeInteger(k), response,
    signature: Buffer.concat([commitment, response]) };
}

function verify(publicKey, message, signature, context) {
  let pub, r, s, k;
  try {
    const dom = domain(context);
    if (!Buffer.isBuffer(signature) || signature.length !== 2 * width || !Buffer.isBuffer(message)) return false;
    pub = decode(publicKey, true);
    r = decode(signature.subarray(0, width));
    s = decodeScalar(signature.subarray(width));
    k = little(shake(dom, signature.subarray(0, width), publicKey, message)) % q;
  } catch (e) {
    if (e instanceof RangeError) return false;
    throw e;
  }
  return equal(multiply(cofactor * s, base), add(multiply(cofactor, r), multiply(cofactor * k, pub)));
}

const fromHex = hex => Buffer.from(hex, 'hex');
const corpus = JSON.parse(readFileSync(new URL('vectors/ed301-eddsa-v2.json', root)));
assert.equal(corpus.parameter_sha256, parameterHash);
assert.equal(encode(base).toString('hex'), parameter.basepoint.G_compressed_edwards_hex);
assert(equal(multiply(q, base), identity));
let intermediates = 0;
for (const v of corpus.signing) {
  const result = trace(fromHex(v.seed_hex), fromHex(v.message_hex), fromHex(v.context_hex));
  assert.deepEqual(Object.keys(result).sort(), Object.keys(v.trace).sort());
  for (const [name, actual] of Object.entries(result)) {
    assert.equal(actual.toString('hex'), v.trace[name], `${v.id}: ${name}`);
    intermediates++;
  }
  assert(verify(result.public_key, fromHex(v.message_hex), result.signature, fromHex(v.context_hex)), v.id);
}
for (const v of corpus.verification)
  assert.equal(verify(fromHex(v.public_key_hex), fromHex(v.message_hex), fromHex(v.signature_hex), fromHex(v.context_hex)), v.accepted, v.id);
for (const v of corpus.point_decoding) {
  if (!v.accepted) assert.throws(() => decode(fromHex(v.encoded_hex)), RangeError, v.id);
  else {
    const point = decode(fromHex(v.encoded_hex));
    assert.equal(point[0], BigInt(v.x), v.id);
    assert.equal(point[1], BigInt(v.y), v.id);
    assert.equal(encode(point).toString('hex'), v.encoded_hex, v.id);
  }
}
for (const v of corpus.scalar_decoding) {
  if (!v.accepted) assert.throws(() => decodeScalar(fromHex(v.encoded_hex)), RangeError, v.id);
  else assert.equal(decodeScalar(fromHex(v.encoded_hex)), BigInt(v.value), v.id);
}
for (const v of corpus.signing_errors)
  assert.throws(() => trace(fromHex(v.seed_hex), fromHex(v.message_hex), fromHex(v.context_hex)), RangeError, v.id);
const empty = Buffer.alloc(0), native = domain(empty);
const controlDomains = {
  'missing-nonce-domain': [empty, native], 'missing-challenge-domain': [native, empty],
  'missing-both-domains': [empty, empty],
  'v1-label-new-curve': [Buffer.from('SigEd301-v1\0\0'), Buffer.from('SigEd301-v1\0\0')],
  'prehash-flag': [Buffer.from('SigEd301-v2\x01\0'), Buffer.from('SigEd301-v2\x01\0')],
};
for (const v of corpus.domain_controls) {
  const result = trace(fromHex(corpus.signing[0].seed_hex), empty, empty, ...controlDomains[v.id]);
  assert.equal(result.nonce_hash.toString('hex'), v.nonce_hash_hex, v.id);
  assert.equal(result.signature.toString('hex'), v.signature_hex, v.id);
  assert.equal(result.signature.toString('hex') === corpus.signing[0].trace.signature, v.matches_signer, v.id);
  assert.equal(verify(result.public_key, empty, result.signature, empty), v.accepted_by_verifier, v.id);
}
const legacy = JSON.parse(readFileSync(new URL('tests/fixtures/v1/ed301-eddsa-v1.json', root)));
const legacyCases = [...legacy.cases, ...legacy.context_cases];
for (const v of legacyCases)
  assert.equal(verify(fromHex(v.public_key_hex), fromHex(v.message_hex), fromHex(v.signature_hex), fromHex(v.context_hex)), false, `v1: ${v.id}`);
console.log(JSON.stringify({ status: 'PASS', oracle: 'Node extended Edwards',
  signing: corpus.signing.length, transcript_intermediates: intermediates,
  verification: corpus.verification.length, point_decoding: corpus.point_decoding.length,
  scalar_decoding: corpus.scalar_decoding.length, signing_errors: corpus.signing_errors.length,
  domain_controls: corpus.domain_controls.length, v1_rejected: legacyCases.length }));
