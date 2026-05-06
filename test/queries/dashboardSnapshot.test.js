const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { afterEach, beforeEach, test } = require('node:test');

const { DataStore } = require('../../src/store');
const { buildDashboardSnapshot } = require('../../src/queries/dashboardSnapshot');

let tempDir;
let store;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'argus-query-dashboard-'));
  store = new DataStore(path.join(tempDir, 'store.db'), 30);
});

afterEach(() => {
  store.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('dashboard snapshot groups monitors and includes incidents and pagination', () => {
  const user = store.createUser({
    username: 'alice',
    passwordHash: 'hash',
    totpSecret: 'SECRET'
  });
  const group = store.createGroup({
    userId: user.id,
    name: 'Ops',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/webhook'
  });
  const monitor = store.createMonitor({
    userId: user.id,
    name: 'API',
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
    lastError: 'HTTP 500',
    lastCheckAt: '2026-01-01T00:00:00.000Z'
  });

  const incident = store.addIncident({
    userId: user.id,
    monitorId: monitor.id,
    monitorName: monitor.name,
    startedAt: '2026-01-01T00:00:00.000Z',
    downReason: 'HTTP 500'
  });

  store.addEvent({
    userId: user.id,
    monitorId: monitor.id,
    monitorName: monitor.name,
    eventType: 'monitor_down',
    message: 'Monitor marked down',
    details: {
      incidentId: incident.id
    }
  });

  const snapshot = buildDashboardSnapshot(store, {
    userId: user.id,
    eventsPage: 1
  });

  assert.equal(snapshot.summary.total, 1);
  assert.equal(snapshot.summary.down, 1);
  assert.equal(snapshot.groupedMonitors.length, 1);
  assert.equal(snapshot.groupedMonitors[0].monitors[0].name, 'API');
  assert.equal(snapshot.activeOutages.length, 1);
  assert.equal(snapshot.incidents.length, 1);
  assert.equal(snapshot.incidentsByMonitor[monitor.id].length, 1);
  assert.equal(snapshot.events.length, 1);
  assert.equal(snapshot.operationalEvents.length, 1);
  assert.equal(snapshot.eventPagination.page, 1);
});

test('dashboard snapshot can omit incidents and events for API usage', () => {
  const user = store.createUser({
    username: 'bob',
    passwordHash: 'hash',
    totpSecret: 'SECRET'
  });

  store.createMonitor({
    userId: user.id,
    name: 'Website',
    checkType: 'http',
    url: 'https://example.com',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/webhook'
  });

  const snapshot = buildDashboardSnapshot(store, {
    userId: user.id,
    includeEvents: false,
    includeIncidents: false
  });

  assert.equal(snapshot.incidents, undefined);
  assert.equal(snapshot.events, undefined);
  assert.equal(snapshot.summary.total, 1);
});
