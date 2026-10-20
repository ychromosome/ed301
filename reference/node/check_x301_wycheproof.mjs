// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as x from './x301.mjs';

const corpus = JSON.parse(readFileSync(new URL('../../vectors/x301-v2-wycheproof.json', import.meta.url)));
const tests = corpus.testGroups[0].tests;
assert.equal(tests.length, corpus.numberOfTests);
for (const test of tests) {
  const secret = Buffer.from(test.private, 'hex');
  const peer = Buffer.from(test.public, 'hex');
  if (test.result === 'valid') {
    assert.equal(x.shared(secret, peer).toString('hex'), test.shared, `tcId ${test.tcId}`);
  } else {
    assert.throws(() => x.shared(secret, peer), x.AllZeroError, `tcId ${test.tcId}`);
  }
}
console.log(JSON.stringify({ status: 'PASS', wycheproof_pattern_cases: tests.length }));
