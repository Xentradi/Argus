const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { afterEach, beforeEach, test } = require('node:test');

const { DataStore } = require('../../src/store');
const { buildPublicStatusSnapshot } = require('../../src/queries/publicStatusSnapshot');

let tempDir;
let store;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'argus-query-public-'));
  store = new DataStore(path.join(tempDir, 'store.db'), 30);
});

afterEach(() => {
  store.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('public status snapshot includes monitor state and durations', () => {
  const user = store.createUser({
    username: 'public',
    passwordHash: 'hash',
    totpSecret: 'SECRET'
  });
  const group = store.createGroup({
    userId: user.id,
    name: 'Public',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/webhook'
  });
  const monitor = store.createMonitor({
    userId: user.id,
    name: 'Public API',
    groupId: group.id,
    groupName: group.name,
    checkType: 'http',
    url: 'https://example.com/health',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/webhook'
  });

  store.updateMonitorRuntime(monitor.id, {
    status: 'down',
    lastFailureAt: '2026-01-01T00:00:00.000Z',
    lastCheckAt: '2026-01-01T00:00:00.000Z',
    lastError: 'HTTP 500'
  });
  store.addIncident({
    userId: user.id,
    monitorId: monitor.id,
    monitorName: monitor.name,
    startedAt: '2026-01-01T00:00:00.000Z',
    downReason: 'HTTP 500'
  });

  const snapshot = buildPublicStatusSnapshot(store, 'public-status', {
    nowMs: new Date('2026-01-01T00:05:00.000Z').getTime()
  });

  assert.equal(snapshot, null);

  store.createStatusPage({
    userId: user.id,
    name: 'Public Status',
    slug: 'public-status',
    monitorIds: [monitor.id]
  });

  const loaded = buildPublicStatusSnapshot(store, 'public-status', {
    nowMs: new Date('2026-01-01T00:05:00.000Z').getTime()
  });

  assert.ok(loaded);
  assert.equal(loaded.statusPage.slug, 'public-status');
  assert.equal(loaded.monitors.length, 1);
  assert.equal(loaded.monitors[0].status, 'down');
  assert.equal(loaded.summary.down, 1);
  assert.ok(loaded.monitors[0].stateDurationSeconds >= 300);
  assert.equal(loaded.uptimeGoalPercent, 99.999);
});
