const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { before, after, test } = require('node:test');

const { runCheck } = require('../src/checkers');

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

test('HTTP mode 2xx accepts 204 responses', async () => {
  const result = await runCheck(
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
  const result = await runCheck(
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
  const result = await runCheck(
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
  const result = await runCheck(
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
