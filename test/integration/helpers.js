const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');

const { DataStore } = require('../../src/store');

const repoRoot = path.join(__dirname, '..', '..');

async function getFreePort() {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  const port = address && typeof address === 'object' ? address.port : null;
  server.close();
  await once(server, 'close');
  assert.ok(port);
  return port;
}

function createTempWorkspace(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return {
    dir,
    dbFile: path.join(dir, 'argus.db'),
    sessionDbFile: 'sessions.db'
  };
}

async function startArgusServer({ dbFile, sessionDbFile, port }) {
  const child = childProcess.spawn(process.execPath, ['src/app.js'], {
    cwd: repoRoot,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      APP_NAME: 'Argus Test',
      PORT: String(port),
      DB_FILE: dbFile,
      SESSION_DB_FILE: sessionDbFile
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  const output = [];
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('Argus server did not start in time'));
    }, 10000);

    const onData = (chunk) => {
      const text = chunk.toString('utf8');
      output.push(text);
      if (text.includes('server_listening')) {
        clearTimeout(timer);
        resolve();
      }
    };

    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      reject(new Error(`Argus server exited early: code=${code} signal=${signal}\n${output.join('')}`));
    });
  });

  await ready;

  return {
    child,
    baseUrl: `http://127.0.0.1:${port}`,
    stop: async () => {
      if (child.exitCode !== null || child.signalCode !== null) {
        return;
      }

      child.kill('SIGTERM');
      await once(child, 'exit');
    }
  };
}

async function requestJson(baseUrl, path, { method = 'GET', headers = {}, body = undefined } = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      ...headers,
      ...(body && !headers['content-type'] && !headers['Content-Type']
        ? { 'content-type': 'application/json' }
        : {})
    },
    body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    redirect: 'manual'
  });

  const contentType = response.headers.get('content-type') || '';
  const raw = await response.text();
  let parsed = null;
  if (contentType.includes('application/json') && raw) {
    parsed = JSON.parse(raw);
  }

  return {
    status: response.status,
    headers: response.headers,
    raw,
    json: parsed
  };
}

function seedApiAccess(dbFile) {
  const store = new DataStore(dbFile, 30);
  const user = store.createUser({
    username: 'integration',
    passwordHash: 'hash',
    totpSecret: 'SECRETINTEGRATION'
  });
  const apiKey = store.createApiKey({
    userId: user.id,
    name: 'integration'
  });
  store.close();

  return {
    user,
    apiKey
  };
}

module.exports = {
  createTempWorkspace,
  getFreePort,
  requestJson,
  seedApiAccess,
  startArgusServer
};
