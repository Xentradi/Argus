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
  workspace = createTempWorkspace('argus-status-flow-');
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

test('public status page reflects API-created monitors', async () => {
  const authHeaders = {
    authorization: `Bearer ${seed.apiKey.token}`
  };

  const monitor = await requestJson(server.baseUrl, '/api/v1/monitors', {
    method: 'POST',
    headers: authHeaders,
    body: {
      name: 'Public API',
      checkType: 'http',
      url: 'https://example.com/public',
      webhookType: 'slack',
      webhookUrl: 'https://example.invalid/webhook'
    }
  });

  const statusPage = await requestJson(server.baseUrl, '/api/v1/status-pages', {
    method: 'POST',
    headers: authHeaders,
    body: {
      name: 'Public Production',
      slug: 'public-production',
      monitorIds: [monitor.json.monitor.id]
    }
  });

  assert.equal(statusPage.status, 201);

  const live = await requestJson(server.baseUrl, '/api/status/public-production/live');
  assert.equal(live.status, 200);
  assert.equal(live.json.statusPage.slug, 'public-production');
  assert.equal(live.json.monitors.length, 1);
  assert.equal(live.json.monitors[0].name, 'Public API');

  const rendered = await requestJson(server.baseUrl, '/status/public-production');
  assert.equal(rendered.status, 200);
  assert.match(rendered.raw, /Public Production/);
  assert.match(rendered.raw, /Public API/);
});
