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

test('status pages can be created, listed, fetched by slug, and deleted', () => {
  const first = store.createMonitor({
    name: 'API',
    checkType: 'http',
    url: 'https://example.com/api',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/slack-webhook'
  });
  const second = store.createMonitor({
    name: 'Worker',
    checkType: 'ping',
    host: '127.0.0.2',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/slack-webhook'
  });

  const created = store.createStatusPage({
    name: 'Public Production',
    slug: 'production-status',
    monitorIds: [first.id, first.id, second.id]
  });

  assert.equal(created.name, 'Public Production');
  assert.equal(created.slug, 'production-status');
  assert.equal(created.monitors.length, 2);

  const listed = store.listStatusPages();
  assert.equal(listed.length, 1);
  assert.equal(listed[0].monitorCount, 2);

  const bySlug = store.getStatusPageBySlug('PRODUCTION-STATUS');
  assert.ok(bySlug);
  assert.equal(bySlug.id, created.id);
  assert.equal(bySlug.monitors.length, 2);

  const removed = store.deleteStatusPage(created.id);
  assert.ok(removed);
  assert.equal(store.getStatusPageById(created.id), null);
});

test('calculateMonitorUptimeStats includes both closed and open incidents', () => {
  const monitor = store.createMonitor({
    name: 'Uptime',
    checkType: 'http',
    url: 'https://example.com/uptime',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/slack-webhook'
  });

  const createdAt = '2026-01-01T00:00:00.000Z';
  store.db.prepare('UPDATE monitors SET created_at = ?, updated_at = ? WHERE id = ?').run(createdAt, createdAt, monitor.id);

  const closedIncident = store.addIncident({
    monitorId: monitor.id,
    monitorName: monitor.name,
    startedAt: '2026-01-01T00:05:00.000Z',
    downReason: 'closed'
  });

  store.closeIncident(closedIncident.id, {
    endedAt: '2026-01-01T00:10:00.000Z',
    recoveryReason: 'recovered'
  });

  store.addIncident({
    monitorId: monitor.id,
    monitorName: monitor.name,
    startedAt: '2026-01-01T00:20:00.000Z',
    downReason: 'open'
  });

  const stats = store.calculateMonitorUptimeStats(monitor.id, '2026-01-01T00:30:00.000Z');

  assert.equal(stats.totalMs, 30 * 60 * 1000);
  assert.equal(stats.downtimeMs, 15 * 60 * 1000);
  assert.equal(stats.uptimeRatio, 0.5);
});

test('scoped listMonitors only returns monitors for the requested user', () => {
  const alice = store.createUser({
    username: 'alice',
    passwordHash: 'hash-a',
    totpSecret: 'SECRETALICE'
  });
  const bob = store.createUser({
    username: 'bob',
    passwordHash: 'hash-b',
    totpSecret: 'SECRETB0B'
  });

  const aliceGroup = store.createGroup({
    userId: alice.id,
    name: 'Alice Group',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/alice'
  });
  const bobGroup = store.createGroup({
    userId: bob.id,
    name: 'Bob Group',
    webhookType: 'discord',
    webhookUrl: 'https://example.invalid/bob'
  });

  store.createMonitor({
    userId: alice.id,
    name: 'Alice API',
    groupId: aliceGroup.id,
    groupName: aliceGroup.name,
    checkType: 'http',
    url: 'https://example.com/alice',
    webhookType: 'slack',
    webhookUrl: 'https://example.invalid/alice'
  });

  store.createMonitor({
    userId: bob.id,
    name: 'Bob API',
    groupId: bobGroup.id,
    groupName: bobGroup.name,
    checkType: 'http',
    url: 'https://example.com/bob',
    webhookType: 'discord',
    webhookUrl: 'https://example.invalid/bob'
  });

  const aliceMonitors = store.listMonitors(alice.id);
  const bobMonitors = store.listMonitors(bob.id);

  assert.equal(aliceMonitors.length, 1);
  assert.equal(aliceMonitors[0].name, 'Alice API');
  assert.equal(bobMonitors.length, 1);
  assert.equal(bobMonitors[0].name, 'Bob API');
});

test('api key authentication validates token and binds to owner', () => {
  const user = store.createUser({
    username: 'apiowner',
    passwordHash: 'hash-api',
    totpSecret: 'SECRETAPI'
  });

  const created = store.createApiKey({
    userId: user.id,
    name: 'integration'
  });

  const auth = store.authenticateApiKey(created.token);
  assert.ok(auth);
  assert.equal(auth.userId, user.id);
  assert.equal(auth.name, 'integration');

  const invalid = store.authenticateApiKey(`${created.token}tampered`);
  assert.equal(invalid, null);
});
