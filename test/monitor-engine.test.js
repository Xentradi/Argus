const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { afterEach, beforeEach, test } = require('node:test');

const { DataStore } = require('../src/store');

let tempDir;
let dbPath;
let store;

const checkersPath = require.resolve('../src/checkers');
const alertsPath = require.resolve('../src/alerts');
const lifecyclePath = require.resolve('../src/domain/monitorLifecycle');
const enginePath = require.resolve('../src/monitorEngine');

let originalCheckers;
let originalAlerts;
let originalLifecycle;
let originalEngine;

function buildResult({ success, checkedAt, reason = null }) {
  return {
    success,
    checkedAt,
    responseMs: success ? 25 : null,
    statusCode: success ? 200 : 503,
    keywordMatched: success ? true : false,
    isTlsError: false,
    reason: success ? null : reason || 'Failure'
  };
}

function buildEngine({ runCheckSequence, sendWebhookAlertImpl, configOverrides = {} }) {
  const sequence = [...runCheckSequence];
  const runCheck = async () => {
    if (sequence.length === 0) {
      throw new Error('No more runCheck results in sequence');
    }
    return sequence.shift();
  };

  require.cache[checkersPath] = { exports: { runCheck } };
  require.cache[alertsPath] = { exports: { sendWebhookAlert: sendWebhookAlertImpl } };
  delete require.cache[lifecyclePath];
  delete require.cache[enginePath];

  const { MonitorEngine } = require('../src/monitorEngine');
  return new MonitorEngine({
    store,
    normalIntervalMs: 1000,
    downIntervalMs: 1000,
    confirmationRetries: 1,
    confirmationRetryIntervalMs: 0,
    minDowntimeBeforeAlertMs: 2000,
    alertCooldownMs: 5000,
    keywordMinDowntimeMs: 3000,
    logger: { error: () => {} },
    ...configOverrides
  });
}

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'argus-engine-test-'));
  dbPath = path.join(tempDir, 'store.db');
  store = new DataStore(dbPath, 30);
  originalCheckers = require.cache[checkersPath];
  originalAlerts = require.cache[alertsPath];
  originalLifecycle = require.cache[lifecyclePath];
  originalEngine = require.cache[enginePath];
});

afterEach(() => {
  store.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
  if (originalCheckers) {
    require.cache[checkersPath] = originalCheckers;
  } else {
    delete require.cache[checkersPath];
  }
  if (originalAlerts) {
    require.cache[alertsPath] = originalAlerts;
  } else {
    delete require.cache[alertsPath];
  }
  if (originalLifecycle) {
    require.cache[lifecyclePath] = originalLifecycle;
  } else {
    delete require.cache[lifecyclePath];
  }
  if (originalEngine) {
    require.cache[enginePath] = originalEngine;
  } else {
    delete require.cache[enginePath];
  }
});

test('brief downtime does not send down or recovery alerts', async () => {
  const t0 = '2024-01-01T00:00:00.000Z';
  const t1 = '2024-01-01T00:00:01.000Z';
  const t2 = '2024-01-01T00:00:01.500Z';
  const t3 = '2024-01-01T00:00:03.000Z';
  const t4 = '2024-01-01T00:00:03.500Z';

  const sendCalls = [];
  const engine = buildEngine({
    runCheckSequence: [
      buildResult({ success: false, checkedAt: t0 }),
      buildResult({ success: false, checkedAt: t1 }),
      buildResult({ success: false, checkedAt: t2 }),
      buildResult({ success: true, checkedAt: t3 }),
      buildResult({ success: true, checkedAt: t4 })
    ],
    sendWebhookAlertImpl: async (...args) => {
      sendCalls.push(args);
      return { ok: true, skipped: false };
    }
  });

  const monitor = store.createMonitor({
    name: 'API',
    checkType: 'http',
    url: 'https://example.com/health',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/slack-webhook'
  });

  await engine.handleUpMonitor(store.getMonitorById(monitor.id));
  await engine.handleDownMonitor(store.getMonitorById(monitor.id));
  await engine.handleDownMonitor(store.getMonitorById(monitor.id));

  assert.equal(sendCalls.length, 0);

  const incidents = store.listIncidents(5);
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].alertedAt, null);
});

test('down alert and recovery alert send after min downtime', async () => {
  const t0 = '2024-01-01T00:00:00.000Z';
  const t1 = '2024-01-01T00:00:01.000Z';
  const t2 = '2024-01-01T00:00:03.500Z';
  const t3 = '2024-01-01T00:00:04.500Z';
  const t4 = '2024-01-01T00:00:04.800Z';

  const sendCalls = [];
  const engine = buildEngine({
    runCheckSequence: [
      buildResult({ success: false, checkedAt: t0 }),
      buildResult({ success: false, checkedAt: t1 }),
      buildResult({ success: false, checkedAt: t2 }),
      buildResult({ success: true, checkedAt: t3 }),
      buildResult({ success: true, checkedAt: t4 })
    ],
    sendWebhookAlertImpl: async (...args) => {
      sendCalls.push(args);
      return { ok: true, skipped: false };
    }
  });

  const monitor = store.createMonitor({
    name: 'API',
    checkType: 'http',
    url: 'https://example.com/health',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/slack-webhook'
  });

  await engine.handleUpMonitor(store.getMonitorById(monitor.id));
  await engine.handleDownMonitor(store.getMonitorById(monitor.id));
  await engine.handleDownMonitor(store.getMonitorById(monitor.id));

  assert.equal(sendCalls.length, 2);

  const incidents = store.listIncidents(5);
  assert.equal(incidents.length, 1);
  assert.ok(incidents[0].alertedAt);
});

test('cooldown suppresses down alert', async () => {
  const t0 = '2024-01-01T00:00:00.000Z';
  const t1 = '2024-01-01T00:00:01.000Z';
  const t2 = '2024-01-01T00:00:03.000Z';
  const lastAlertAt = '2024-01-01T00:00:02.000Z';

  const sendCalls = [];
  const engine = buildEngine({
    runCheckSequence: [
      buildResult({ success: false, checkedAt: t0 }),
      buildResult({ success: false, checkedAt: t1 }),
      buildResult({ success: false, checkedAt: t2 })
    ],
    sendWebhookAlertImpl: async (...args) => {
      sendCalls.push(args);
      return { ok: true, skipped: false };
    }
  });

  const monitor = store.createMonitor({
    name: 'API',
    checkType: 'http',
    url: 'https://example.com/health',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/slack-webhook'
  });

  await engine.handleUpMonitor(store.getMonitorById(monitor.id));
  store.updateMonitorRuntime(monitor.id, { lastAlertDownAt: lastAlertAt });
  await engine.handleDownMonitor(store.getMonitorById(monitor.id));

  assert.equal(sendCalls.length, 0);

  const incidents = store.listIncidents(5);
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].alertedAt, null);
});

test('keyword monitors use keyword min downtime by default', async () => {
  const t0 = '2024-01-01T00:00:00.000Z';
  const t1 = '2024-01-01T00:00:01.000Z';
  const t2 = '2024-01-01T00:00:02.000Z';
  const t3 = '2024-01-01T00:00:04.000Z';

  const sendCalls = [];
  const engine = buildEngine({
    runCheckSequence: [
      buildResult({ success: false, checkedAt: t0 }),
      buildResult({ success: false, checkedAt: t1 }),
      buildResult({ success: false, checkedAt: t2 }),
      buildResult({ success: false, checkedAt: t3 })
    ],
    sendWebhookAlertImpl: async (...args) => {
      sendCalls.push(args);
      return { ok: true, skipped: false };
    },
    configOverrides: {
      minDowntimeBeforeAlertMs: 1000,
      keywordMinDowntimeMs: 3000
    }
  });

  const monitor = store.createMonitor({
    name: 'Keyword',
    checkType: 'keyword',
    url: 'https://example.com/keyword',
    keyword: 'OK',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/slack-webhook'
  });

  await engine.handleUpMonitor(store.getMonitorById(monitor.id));
  await engine.handleDownMonitor(store.getMonitorById(monitor.id));
  await engine.handleDownMonitor(store.getMonitorById(monitor.id));

  assert.equal(sendCalls.length, 1);
});
