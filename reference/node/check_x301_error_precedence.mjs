// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as x from './x301.mjs';

const corpus = JSON.parse(readFileSync(new URL('../../vectors/x301-error-precedence.json', import.meta.url)));
const messages = {
  InvalidSecretLength: ['secret length/type'], WeakSecret: ['twist-order secret'],
  InvalidPublicLength: ['u length/type'], NonCanonicalPublic: ['u reserved bits', 'u noncanonical'],
};
let count = 0;
for (const secret of corpus.secrets) {
  for (const peer of corpus.peers) {
    const expected = secret.error ?? peer.error;
    if (expected === null) continue;
    const calls = x.diagnostics.ladderCalls;
    assert.throws(() => x.shared(Buffer.from(secret.hex, 'hex'), Buffer.from(peer.hex, 'hex')),
      error => error instanceof RangeError
        && (error instanceof x.WeakSecretError) === (expected === 'WeakSecret')
        && messages[expected].includes(error.message), `${secret.id}/${peer.id}`);
    assert.equal(x.diagnostics.ladderCalls, calls);
    count++;
  }
}
assert.equal(count, 39);
console.log(JSON.stringify({ status: 'PASS', error_precedence_cases: count }));
