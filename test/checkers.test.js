const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { before, after, test } = require('node:test');
const childProcess = require('node:child_process');

const { runHttpCheck } = require('../src/checks/http');
const { runKeywordCheck } = require('../src/checks/keyword');

let server;
let baseUrl;

function monitor(overrides) {
  return {
    checkType: 'http',
    host: '',
    url: '',
    keyword: '',
    keywordCaseSensitive: false,
    httpStatusMode: '2xx',
    tlsErrorAsFailure: true,
    timeoutMs: 5000,
    ...overrides
  };
}

before(async () => {
  server = http.createServer((req, res) => {
    if (req.url === '/ok-200') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('healthy');
      return;
    }

    if (req.url === '/ok-204') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.url === '/keyword') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('The Service Is READY');
      return;
    }

    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');

  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  server.close();
  await once(server, 'close');
});

function loadPingAdapterWithStub(execFileImpl) {
  const originalExecFile = childProcess.execFile;
  childProcess.execFile = execFileImpl;

  const pingPath = require.resolve('../src/checks/ping');
  delete require.cache[pingPath];

  return () => {
    childProcess.execFile = originalExecFile;
    delete require.cache[pingPath];
  };
}

test('HTTP mode 2xx accepts 204 responses', async () => {
  const result = await runHttpCheck(
    monitor({
      checkType: 'http',
      url: `${baseUrl}/ok-204`,
      httpStatusMode: '2xx'
    })
  );

  assert.equal(result.success, true);
  assert.equal(result.statusCode, 204);
});

test('HTTP mode 200 rejects 204 responses', async () => {
  const result = await runHttpCheck(
    monitor({
      checkType: 'http',
      url: `${baseUrl}/ok-204`,
      httpStatusMode: '200'
    })
  );

  assert.equal(result.success, false);
  assert.equal(result.statusCode, 204);
  assert.match(result.reason, /expected 200/i);
});

test('keyword check supports case-insensitive matching', async () => {
  const result = await runKeywordCheck(
    monitor({
      checkType: 'keyword',
      url: `${baseUrl}/keyword`,
      keyword: 'ready',
      keywordCaseSensitive: false,
      httpStatusMode: '2xx'
    })
  );

  assert.equal(result.success, true);
  assert.equal(result.keywordMatched, true);
});

test('keyword check can enforce case-sensitive matching', async () => {
  const result = await runKeywordCheck(
    monitor({
      checkType: 'keyword',
      url: `${baseUrl}/keyword`,
      keyword: 'ready',
      keywordCaseSensitive: true,
      httpStatusMode: '2xx'
    })
  );

  assert.equal(result.success, false);
  assert.equal(result.keywordMatched, false);
  assert.match(result.reason, /not found/i);
});

test('ping adapter succeeds when at least one probe replies', async () => {
  const restore = loadPingAdapterWithStub((command, args, options, callback) => {
    assert.equal(command, 'ping');
    if (process.platform === 'win32') {
      assert.deepEqual(args.slice(0, 2), ['-n', '3']);
    } else {
      assert.deepEqual(args.slice(0, 2), ['-c', '3']);
    }

    callback(
      Object.assign(new Error('ping exited with code 1'), { code: 1, killed: false }),
      '3 packets transmitted, 2 received, 33% packet loss\n',
      ''
    );
  });

  try {
    const { runPingCheck } = require('../src/checks/ping');
    const result = await runPingCheck('203.0.113.10', 1000);

    assert.equal(result.success, true);
    assert.equal(result.reason, null);
  } finally {
    restore();
  }
});

test('ping adapter reports 100% loss only when all probes fail', async () => {
  const restore = loadPingAdapterWithStub((command, args, options, callback) => {
    assert.equal(command, 'ping');
    if (process.platform === 'win32') {
      assert.deepEqual(args.slice(0, 2), ['-n', '3']);
    } else {
      assert.deepEqual(args.slice(0, 2), ['-c', '3']);
    }

    callback(
      Object.assign(new Error('ping exited with code 1'), { code: 1, killed: false }),
      '3 packets transmitted, 0 received, 100% packet loss\n',
      ''
    );
  });

  try {
    const { runPingCheck } = require('../src/checks/ping');
    const result = await runPingCheck('203.0.113.10', 1000);

    assert.equal(result.success, false);
    assert.match(result.reason, /0\/3 replies/);
  } finally {
    restore();
  }
});

test('dispatcher routes ping checks to the ping adapter', async () => {
  const pingPath = require.resolve('../src/checks/ping');
  const httpPath = require.resolve('../src/checks/http');
  const keywordPath = require.resolve('../src/checks/keyword');
  const checkersPath = require.resolve('../src/checkers');

  const originalPing = require.cache[pingPath];
  const originalHttp = require.cache[httpPath];
  const originalKeyword = require.cache[keywordPath];
  const originalCheckers = require.cache[checkersPath];

  const calls = [];

  require.cache[pingPath] = {
    exports: {
      runPingCheck: async (host, timeoutMs) => {
        calls.push(['ping', host, timeoutMs]);
        return { success: true, checkedAt: '2024-01-01T00:00:00.000Z', responseMs: 1, statusCode: null, keywordMatched: null, isTlsError: false, reason: null };
      }
    }
  };
  require.cache[httpPath] = {
    exports: {
      runHttpCheck: async (monitor) => {
        calls.push(['http', monitor.checkType]);
        return { success: true, checkedAt: '2024-01-01T00:00:00.000Z', responseMs: 1, statusCode: 200, keywordMatched: null, isTlsError: false, reason: null };
      }
    }
  };
  require.cache[keywordPath] = {
    exports: {
      runKeywordCheck: async (monitor) => {
        calls.push(['keyword', monitor.checkType]);
        return { success: true, checkedAt: '2024-01-01T00:00:00.000Z', responseMs: 1, statusCode: 200, keywordMatched: true, isTlsError: false, reason: null };
      }
    }
  };

  delete require.cache[checkersPath];
  const { runCheck } = require('../src/checkers');

  try {
    const result = await runCheck({
      checkType: 'ping',
      host: '127.0.0.1',
      timeoutMs: 123
    });

    assert.equal(result.success, true);
    assert.deepEqual(calls, [['ping', '127.0.0.1', 123]]);
  } finally {
    if (originalPing) {
      require.cache[pingPath] = originalPing;
    } else {
      delete require.cache[pingPath];
    }
    if (originalHttp) {
      require.cache[httpPath] = originalHttp;
    } else {
      delete require.cache[httpPath];
    }
    if (originalKeyword) {
      require.cache[keywordPath] = originalKeyword;
    } else {
      delete require.cache[keywordPath];
    }
    if (originalCheckers) {
      require.cache[checkersPath] = originalCheckers;
    } else {
      delete require.cache[checkersPath];
    }
  }
});
