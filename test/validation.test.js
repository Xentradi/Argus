const assert = require('node:assert/strict');
const { test } = require('node:test');

const { createMonitorValidation, createGroupValidation, createStatusPageValidation } = require('../src/validation');

const monitorValidation = createMonitorValidation({
  store: {
    getGroupById: (id) =>
      id === 'group-1'
        ? {
            id: 'group-1',
            name: 'Ops',
            webhookType: 'slack',
            webhookUrl: 'https://example.invalid/webhook'
          }
        : null
  },
  config: {
    minTimeoutMs: 1000,
    maxTimeoutMs: 10000,
    defaultTimeoutMs: 5000
  },
  clampNumber: (value, min, max, fallback) => {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) {
      return fallback;
    }
    return Math.max(min, Math.min(max, parsed));
  },
  isLikelyUrl: (value) => /^https?:\/\//.test(String(value || '')),
  normalizeUrl: (value) => String(value || '').trim(),
  safeLower: (value) => String(value || '').trim().toLowerCase()
});

const groupValidation = createGroupValidation({
  normalizeUrl: (value) => String(value || '').trim(),
  safeLower: (value) => String(value || '').trim().toLowerCase(),
  isLikelyUrl: (value) => /^https?:\/\//.test(String(value || ''))
});

const statusPageValidation = createStatusPageValidation();

test('monitor validation accepts ping monitors and inherited group settings', () => {
  const result = monitorValidation.parseMonitorForm(
    {
      name: 'Gateway',
      checkType: 'ping',
      host: '127.0.0.1',
      groupId: 'group-1',
      timeoutMs: '2500',
      active: 'on'
    },
    null,
    'user-1'
  );

  assert.deepEqual(result.errors, []);
  assert.equal(result.monitorPayload.groupName, 'Ops');
  assert.equal(result.monitorPayload.webhookType, 'slack');
  assert.equal(result.monitorPayload.timeoutMs, 2500);
});

test('monitor validation normalizes API bodies onto existing monitors', () => {
  const normalized = monitorValidation.normalizeApiMonitorBody(
    {
      active: false,
      timeoutMs: 9000
    },
    {
      name: 'API',
      groupId: 'group-1',
      checkType: 'http',
      host: '',
      url: 'https://example.com',
      keyword: '',
      keywordCaseSensitive: false,
      httpStatusMode: '2xx',
      tlsErrorAsFailure: true,
      webhookType: 'slack',
      webhookUrl: 'https://example.invalid/webhook',
      timeoutMs: 5000,
      minDowntimeMs: null,
      alertCooldownMs: null,
      active: true
    }
  );

  assert.equal(normalized.active, '');
  assert.equal(normalized.timeoutMs, 9000);
  assert.equal(normalized.checkType, 'http');
  assert.equal(normalized.groupId, 'group-1');
});

test('group validation rejects invalid webhook data', () => {
  const result = groupValidation.parseGroupForm({
    name: '',
    webhookType: 'fax',
    webhookUrl: 'ftp://example.com'
  });

  assert.ok(result.errors.includes('Group name is required.'));
  assert.ok(result.errors.includes('Webhook type must be Slack or Discord.'));
  assert.ok(result.errors.includes('A valid webhook URL is required.'));
});

test('status page validation requires a slug and at least one monitor', () => {
  const result = statusPageValidation.parseStatusPageForm({
    name: 'Production',
    slug: 'production-status',
    monitorIds: []
  });

  assert.ok(result.errors.includes('Select at least one monitor.'));
});
