const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { beforeEach, afterEach, test } = require('node:test');

const { DataStore } = require('../src/store');

let tempDir;
let dbPath;
let store;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'argus-test-'));
  dbPath = path.join(tempDir, 'store.db');
  store = new DataStore(dbPath, 30);
});

afterEach(() => {
  store.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('createMonitor defaults to group "Default" and HTTP mode "2xx"', () => {
  const created = store.createMonitor({
    name: 'Website',
    checkType: 'http',
    url: 'https://example.com/health',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/slack-webhook'
  });

  assert.equal(created.groupName, 'Default');
  assert.equal(created.httpStatusMode, '2xx');

  const loaded = store.getMonitorById(created.id);
  assert.equal(loaded.groupName, 'Default');
  assert.equal(loaded.httpStatusMode, '2xx');
});

test('updateMonitor persists group changes', () => {
  const created = store.createMonitor({
    name: 'Gateway',
    checkType: 'ping',
    host: '127.0.0.1',
    groupName: 'Company A',
    webhookType: 'discord',
    webhookUrl: 'https://example.invalid/discord-webhook'
  });

  const updated = store.updateMonitor(created.id, {
    groupName: 'Company B'
  });

  assert.equal(updated.groupName, 'Company B');
  assert.equal(store.getMonitorById(created.id).groupName, 'Company B');
});

test('pruneOldHistory removes old incidents and events based on retention', () => {
  const created = store.createMonitor({
    name: 'Retention Test',
    checkType: 'http',
    url: 'https://example.com',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/slack-webhook'
  });

  const oldStart = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString();
  const oldEnd = new Date(Date.now() - 59 * 24 * 60 * 60 * 1000).toISOString();

  const oldIncident = store.addIncident({
    monitorId: created.id,
    monitorName: created.name,
    startedAt: oldStart,
    downReason: 'old outage'
  });

  store.closeIncident(oldIncident.id, {
    endedAt: oldEnd,
    recoveryReason: 'old recovery'
  });

  const oldEvent = store.addEvent({
    monitorId: created.id,
    monitorName: created.name,
    eventType: 'old_event',
    message: 'old event'
  });

  store.db.prepare('UPDATE events SET created_at = ? WHERE id = ?').run(oldStart, oldEvent.id);

  const result = store.pruneOldHistory();

  assert.ok(result.deletedIncidents >= 1);
  assert.ok(result.deletedEvents >= 1);

  const incidents = store.listIncidents(50);
  const events = store.listEvents(50);

  assert.equal(incidents.some((incident) => incident.id === oldIncident.id), false);
  assert.equal(events.some((event) => event.id === oldEvent.id), false);
});
