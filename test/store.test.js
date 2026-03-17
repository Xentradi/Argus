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

test('createMonitor defaults to ungrouped and HTTP mode "2xx"', () => {
  const created = store.createMonitor({
    name: 'Website',
    checkType: 'http',
    url: 'https://example.com/health',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/slack-webhook'
  });

  assert.equal(created.groupId, null);
  assert.equal(created.groupName, '');
  assert.equal(created.httpStatusMode, '2xx');

  const loaded = store.getMonitorById(created.id);
  assert.equal(loaded.groupId, null);
  assert.equal(loaded.groupName, '');
  assert.equal(loaded.httpStatusMode, '2xx');
});

test('group updates propagate webhook settings to group monitors', () => {
  const group = store.createGroup({
    name: 'Company A',
    webhookType: 'discord',
    webhookUrl: 'https://example.invalid/discord-webhook'
  });

  const created = store.createMonitor({
    name: 'Gateway',
    checkType: 'ping',
    host: '127.0.0.1',
    groupId: group.id,
    groupName: group.name,
    webhookType: group.webhookType,
    webhookUrl: group.webhookUrl
  });

  const updatedGroup = store.updateGroup(group.id, {
    name: 'Company B',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/slack-webhook'
  });

  assert.equal(updatedGroup.name, 'Company B');

  const loaded = store.getMonitorById(created.id);
  assert.equal(loaded.groupName, 'Company B');
  assert.equal(loaded.webhookType, 'slack');
  assert.equal(loaded.webhookUrl, 'https://example.invalid/slack-webhook');
});

test('moveMonitorInGroup swaps ordering within its group', () => {
  const group = store.createGroup({
    name: 'Ops',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/ops-webhook'
  });

  const alpha = store.createMonitor({
    name: 'Alpha',
    checkType: 'ping',
    host: '127.0.0.1',
    groupId: group.id,
    groupName: group.name,
    webhookType: group.webhookType,
    webhookUrl: group.webhookUrl
  });

  const bravo = store.createMonitor({
    name: 'Bravo',
    checkType: 'ping',
    host: '127.0.0.2',
    groupId: group.id,
    groupName: group.name,
    webhookType: group.webhookType,
    webhookUrl: group.webhookUrl
  });

  assert.ok(alpha.sortOrder < bravo.sortOrder);

  store.moveMonitorInGroup(bravo.id, 'up');

  const movedAlpha = store.getMonitorById(alpha.id);
  const movedBravo = store.getMonitorById(bravo.id);
  assert.ok(movedBravo.sortOrder < movedAlpha.sortOrder);
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
