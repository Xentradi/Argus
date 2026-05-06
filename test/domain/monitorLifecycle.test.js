const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { afterEach, beforeEach, test } = require('node:test');

const { DataStore } = require('../../src/store');
const { createRepositories } = require('../../src/repositories');
const { MonitorLifecycle } = require('../../src/domain/monitorLifecycle');

let tempDir;
let store;
let repositories;

function buildResult({ success, checkedAt, reason = null }) {
  return {
    success,
    checkedAt,
    responseMs: success ? 22 : null,
    statusCode: success ? 200 : 503,
    keywordMatched: success ? true : false,
    isTlsError: false,
    reason: success ? null : reason || 'Failure'
  };
}

function buildLifecycle({ runCheckSequence, sendWebhookAlertImpl = async () => ({ ok: true, skipped: false }) }) {
  const sequence = [...runCheckSequence];
  const runCheckImpl = async () => {
    if (sequence.length === 0) {
      throw new Error('No more runCheck results in sequence');
    }
    return sequence.shift();
  };

  return new MonitorLifecycle({
    monitorRepository: repositories.monitors,
    incidentRepository: repositories.incidents,
    eventRepository: repositories.events,
    normalIntervalMs: 1000,
    downIntervalMs: 500,
    confirmationRetries: 1,
    confirmationRetryIntervalMs: 0,
    minDowntimeBeforeAlertMs: 1000,
    alertCooldownMs: 5000,
    keywordMinDowntimeMs: 3000,
    runCheckImpl,
    sendWebhookAlertImpl,
    sleepImpl: async () => {},
    logger: { error: () => {} }
  });
}

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'argus-lifecycle-test-'));
  store = new DataStore(path.join(tempDir, 'store.db'), 30);
  repositories = createRepositories(store);
});

afterEach(() => {
  store.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('transient failure stays up and does not create an incident', async () => {
  const lifecycle = buildLifecycle({
    runCheckSequence: [
      buildResult({ success: false, checkedAt: '2024-01-01T00:00:00.000Z' }),
      buildResult({ success: true, checkedAt: '2024-01-01T00:00:01.000Z' })
    ]
  });

  const monitor = store.createMonitor({
    name: 'API',
    checkType: 'http',
    url: 'https://example.com/health',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/webhook'
  });

  const nextDelay = await lifecycle.handleUpMonitor(store.getMonitorById(monitor.id));

  assert.equal(nextDelay, 1000);
  assert.equal(store.listIncidents(5).length, 0);
  assert.equal(store.getMonitorById(monitor.id).runtime.status, 'up');
  assert.equal(store.getMonitorById(monitor.id).runtime.lastError, null);
  assert.ok(store.getMonitorById(monitor.id).runtime.lastFailureAt);
});

test('confirmed failure creates an incident and sends a down alert', async () => {
  const sendCalls = [];
  const lifecycle = buildLifecycle({
    runCheckSequence: [
      buildResult({ success: false, checkedAt: '2024-01-01T00:00:00.000Z' }),
      buildResult({ success: false, checkedAt: '2024-01-01T00:00:01.500Z' }),
      buildResult({ success: false, checkedAt: '2024-01-01T00:00:03.000Z' })
    ],
    sendWebhookAlertImpl: async (...args) => {
      sendCalls.push(args);
      return { ok: true, skipped: false };
    }
  });

  const monitor = store.createMonitor({
    name: 'Gateway',
    checkType: 'http',
    url: 'https://example.com/health',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/webhook'
  });

  const firstDelay = await lifecycle.handleUpMonitor(store.getMonitorById(monitor.id));
  const secondDelay = await lifecycle.handleDownMonitor(store.getMonitorById(monitor.id));

  assert.equal(firstDelay, 500);
  assert.equal(secondDelay, 500);
  assert.equal(sendCalls.length, 1);

  const incidents = store.listIncidents(5);
  assert.equal(incidents.length, 1);
  assert.ok(incidents[0].alertedAt);
  assert.equal(store.getMonitorById(monitor.id).runtime.status, 'down');
});

test('recovery closes the incident and sends a recovery alert', async () => {
  const sendCalls = [];
  const lifecycle = buildLifecycle({
    runCheckSequence: [
      buildResult({ success: false, checkedAt: '2024-01-01T00:00:00.000Z' }),
      buildResult({ success: false, checkedAt: '2024-01-01T00:00:01.500Z' }),
      buildResult({ success: false, checkedAt: '2024-01-01T00:00:03.000Z' }),
      buildResult({ success: true, checkedAt: '2024-01-01T00:00:05.000Z' }),
      buildResult({ success: true, checkedAt: '2024-01-01T00:00:06.000Z' })
    ],
    sendWebhookAlertImpl: async (...args) => {
      sendCalls.push(args);
      return { ok: true, skipped: false };
    }
  });

  const monitor = store.createMonitor({
    name: 'Gateway',
    checkType: 'http',
    url: 'https://example.com/health',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/webhook'
  });

  await lifecycle.handleUpMonitor(store.getMonitorById(monitor.id));
  await lifecycle.handleDownMonitor(store.getMonitorById(monitor.id));
  const recoveryDelay = await lifecycle.handleDownMonitor(store.getMonitorById(monitor.id));

  assert.equal(recoveryDelay, 1000);
  assert.equal(sendCalls.length, 2);

  const incidents = store.listIncidents(5);
  assert.equal(incidents.length, 1);
  assert.ok(incidents[0].endedAt);
  assert.ok(incidents[0].durationSeconds >= 2);
  assert.equal(store.getMonitorById(monitor.id).runtime.status, 'up');
});
