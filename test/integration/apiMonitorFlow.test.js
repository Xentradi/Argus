const assert = require('node:assert/strict');
const fs = require('node:fs');
const { afterEach, beforeEach, test } = require('node:test');

const {
  createTempWorkspace,
  getFreePort,
  requestJson,
  seedApiAccess,
  startArgusServer
} = require('./helpers');

let workspace;
let port;
let seed;
let server;

beforeEach(async () => {
  workspace = createTempWorkspace('argus-api-flow-');
  port = await getFreePort();
  seed = seedApiAccess(workspace.dbFile);
  server = await startArgusServer({
    dbFile: workspace.dbFile,
    sessionDbFile: workspace.sessionDbFile,
    port
  });
});

afterEach(async () => {
  if (server) {
    await server.stop();
  }

  if (workspace) {
    fs.rmSync(workspace.dir, { recursive: true, force: true });
  }
});

test('API flow can create, update, pause, resume, and delete monitors', async () => {
  const authHeaders = {
    authorization: `Bearer ${seed.apiKey.token}`
  };

  const created = await requestJson(server.baseUrl, '/api/v1/monitors', {
    method: 'POST',
    headers: authHeaders,
    body: {
      name: 'Integration API',
      checkType: 'http',
      url: 'https://example.com/health',
      webhookType: 'slack',
      webhookUrl: 'https://example.invalid/webhook'
    }
  });

  assert.equal(created.status, 201);
  assert.equal(created.json.monitor.name, 'Integration API');
  assert.equal(created.json.monitor.active, false);
  assert.equal(created.json.monitor.statusClass, 'paused');

  const monitorId = created.json.monitor.id;

  const updated = await requestJson(server.baseUrl, `/api/v1/monitors/${monitorId}`, {
    method: 'PATCH',
    headers: authHeaders,
    body: {
      name: 'Integration API Updated'
    }
  });

  assert.equal(updated.status, 200);
  assert.equal(updated.json.monitor.name, 'Integration API Updated');

  const paused = await requestJson(server.baseUrl, `/api/v1/monitors/${monitorId}/pause`, {
    method: 'POST',
    headers: authHeaders
  });

  assert.equal(paused.status, 200);
  assert.equal(paused.json.monitor.active, false);
  assert.equal(paused.json.monitor.statusClass, 'paused');

  const resumed = await requestJson(server.baseUrl, `/api/v1/monitors/${monitorId}/resume`, {
    method: 'POST',
    headers: authHeaders
  });

  assert.equal(resumed.status, 200);
  assert.equal(resumed.json.monitor.active, true);

  const statusPage = await requestJson(server.baseUrl, '/api/v1/status-pages', {
    method: 'POST',
    headers: authHeaders,
    body: {
      name: 'Integration Status',
      slug: 'integration-status',
      monitorIds: [monitorId]
    }
  });

  assert.equal(statusPage.status, 201);
  assert.equal(statusPage.json.statusPage.slug, 'integration-status');
  assert.equal(statusPage.json.statusPage.monitors.length, 1);

  const livePage = await requestJson(server.baseUrl, '/api/status/integration-status/live');
  assert.equal(livePage.status, 200);
  assert.equal(livePage.json.statusPage.slug, 'integration-status');
  assert.equal(livePage.json.summary.total, 1);

  const deleted = await requestJson(server.baseUrl, `/api/v1/monitors/${monitorId}`, {
    method: 'DELETE',
    headers: authHeaders
  });

  assert.equal(deleted.status, 200);
  assert.equal(deleted.json.deleted, true);
});
