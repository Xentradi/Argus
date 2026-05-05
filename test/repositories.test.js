const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { afterEach, beforeEach, test } = require('node:test');

const { DataStore } = require('../src/store');
const { createRepositories } = require('../src/repositories');

let tempDir;
let dbPath;
let baseStore;
let repositories;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'argus-repo-test-'));
  dbPath = path.join(tempDir, 'store.db');
  baseStore = new DataStore(dbPath, 30);
  repositories = createRepositories(baseStore);
});

afterEach(() => {
  baseStore.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('repository facade keeps legacy helpers and exposes focused namespaces', () => {
  assert.equal(typeof repositories.users.findUserById, 'function');
  assert.equal(typeof repositories.groups.listGroups, 'function');
  assert.equal(typeof repositories.monitors.createMonitor, 'function');
  assert.equal(typeof repositories.statusPages.listStatusPages, 'function');
  assert.equal(typeof repositories.incidents.listIncidents, 'function');
  assert.equal(typeof repositories.events.listEvents, 'function');
  assert.equal(typeof repositories.apiKeys.createApiKey, 'function');
});

test('repository facade delegates through the grouped namespaces', () => {
  const user = repositories.createUser({
    username: 'alice',
    passwordHash: 'hash',
    totpSecret: 'secret'
  });

  const apiKey = repositories.createApiKey({
    userId: user.id,
    name: 'cli'
  });

  const auth = repositories.authenticateApiKey(apiKey.token);

  assert.equal(auth.userId, user.id);
  assert.equal(repositories.findUserByUsername('alice').id, user.id);
  assert.equal(repositories.users.findUserById(user.id).id, user.id);
});
