const assert = require('node:assert/strict');
const { test } = require('node:test');

const { assertRuntimePatchConsistency } = require('../../src/domain/invariants');

test('runtime patch invariant rejects mismatched transition status', () => {
  assert.throws(
    () =>
      assertRuntimePatchConsistency({
        transition: 'down',
        patch: {
          status: 'up',
          nextCheckAt: null
        }
      }),
    /preserve the requested transition status/
  );
});

test('runtime patch invariant rejects missing nextCheckAt reset', () => {
  assert.throws(
    () =>
      assertRuntimePatchConsistency({
        transition: 'up',
        patch: {
          status: 'up',
          nextCheckAt: '2026-01-01T00:00:00.000Z'
        }
      }),
    /clear nextCheckAt/
  );
});
