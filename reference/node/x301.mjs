// SPDX-License-Identifier: Apache-2.0
// Independent-language X301 test oracle. BigInt arithmetic is NOT constant-time.
// Uses add-and-double pair selection, not the Python ladder's swap schedule.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';

const input = readFileSync(new URL('../../provenance/phase-a/2026-09-09/parameter/ed301-v2.json', import.meta.url));
export const parameterHash = '13f0eaf541919a1447b9d3c58e6d57eb77ffab94ebe37539c70301d6fddcfaa0';
if (createHash('sha256').update(input).digest('hex') !== parameterHash) throw new Error('Gate-A hash mismatch');
const parameters = JSON.parse(input);
export const p = BigInt(parameters.field.p_decimal);
export const nt = BigInt(parameters.twist.order_decimal);
export const width = parameters.encoding.field_bytes;
export const bits = parameters.field.bit_length;
export const a24 = BigInt(parameters.montgomery.A24_minus_decimal);
export const base = Buffer.from(parameters.basepoint.G_montgomery_u_little_endian_hex, 'hex');
export const diagnostics = { ladderCalls: 0, rounds: 0 }; // Test-only oracle instrumentation.
const mod = n => ((n % p) + p) % p;

export class WeakSecretError extends RangeError {}
export class AllZeroError extends RangeError {}

export function little(bytes) {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; --i) result = result * 256n + BigInt(bytes[i]);
  return result;
}

export function encode(value) {
  if (typeof value !== 'bigint' || value < 0n || value >= p) throw new RangeError('field range');
  const out = Buffer.alloc(width);
  for (let i = 0; i < width; ++i, value >>= 8n) out[i] = Number(value & 255n);
  return out;
}

export function decode(input) {
  if (!Buffer.isBuffer(input) || input.length !== width) throw new RangeError('u length/type');
  if (input[width - 1] & 0xe0) throw new RangeError('u reserved bits');
  const u = little(input);
  if (u >= p) throw new RangeError('u noncanonical');
  return u;
}

export function clamp(secret) {
  if (!Buffer.isBuffer(secret) || secret.length !== width) throw new RangeError('secret length/type');
  const out = Buffer.from(secret);
  out[0] &= 0xfc;
  out[width - 1] = (out[width - 1] & 15) | 16;
  if (timingSafeEqual(out, encode(nt))) throw new WeakSecretError('twist-order secret');
  return out;
}

export function importSecret(secret) {
  clamp(secret);
  return Buffer.from(secret);
}

function inverse(value) {
  let result = 1n;
  for (const bit of (p - 2n).toString(2)) {
    result = mod(result * result);
    if (bit === '1') result = mod(result * value);
  }
  return result;
}

function double([x, z]) {
  const plusSquared = mod((x + z) ** 2n), minusSquared = mod((x - z) ** 2n);
  const difference = mod(plusSquared - minusSquared);
  return [mod(plusSquared * minusSquared), mod(difference * (plusSquared + a24 * difference))];
}

function differentialAdd([x0, z0], [x1, z1], differenceU) {
  const cross0 = mod((x0 + z0) * (x1 - z1));
  const cross1 = mod((x0 - z0) * (x1 + z1));
  return [mod((cross0 + cross1) ** 2n), mod(differenceU * (cross0 - cross1) ** 2n)];
}

export function ladder(scalar, u) {
  if (typeof scalar !== 'bigint' || scalar < 0n || scalar >= 1n << BigInt(bits) ||
      typeof u !== 'bigint' || u < 0n || u >= p) throw new RangeError('ladder input');
  diagnostics.ladderCalls++;
  diagnostics.rounds = 0;
  let r0 = [1n, 0n], r1 = [u, 1n];
  for (let index = bits - 1; index >= 0; --index) {
    const sum = differentialAdd(r0, r1, u);
    if ((scalar >> BigInt(index)) & 1n) [r0, r1] = [sum, double(r1)];
    else [r0, r1] = [double(r0), sum];
    diagnostics.rounds++;
  }
  return r0;
}

export function finalize([x, z]) {
  if (mod(z) === 0n) throw new AllZeroError('point at infinity');
  const output = encode(mod(x * inverse(mod(z))));
  if (timingSafeEqual(output, Buffer.alloc(width))) throw new AllZeroError('all-zero coordinate');
  return output;
}

export function x301(secret, peer) {
  const scalar = little(clamp(secret));
  const u = decode(peer);
  return finalize(ladder(scalar, u));
}

export const publicKey = secret => x301(secret, base);
export const shared = x301;

export function keygen(random = randomBytes) {
  for (;;) {
    const secret = random(width);
    try {
      const pub = publicKey(secret);
      return [Buffer.from(secret), pub];
    } catch (error) {
      if (error instanceof WeakSecretError) continue;
      throw error;
    }
  }
}
