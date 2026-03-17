const assert = require('node:assert/strict');
const { test } = require('node:test');

const config = require('../src/config');
const { buildWebhookBody, buildAlertMessage } = require('../src/alerts');

test('Slack webhook body includes custom Argus identity fields', () => {
  const body = buildWebhookBody('slack', 'hello');

  assert.equal(body.text, 'hello');
  assert.equal(body.username, config.webhookDisplayName);
  assert.equal(body.username, 'Argus');
  if (config.webhookIconUrl) {
    assert.equal(body.icon_url, config.webhookIconUrl);
  } else {
    assert.equal(body.icon_url, undefined);
  }
});

test('Discord webhook body includes custom Argus identity fields', () => {
  const body = buildWebhookBody('discord', 'hello');

  assert.equal(body.content, 'hello');
  assert.equal(body.username, config.webhookDisplayName);
  assert.equal(body.username, 'Argus');
  if (config.webhookIconUrl) {
    assert.equal(body.avatar_url, config.webhookIconUrl);
  } else {
    assert.equal(body.avatar_url, undefined);
  }
});

test('status alert message includes current monitor state', () => {
  const message = buildAlertMessage(
    {
      name: 'Gateway',
      checkType: 'ping',
      host: '203.0.113.10',
      url: '',
      runtime: {
        status: 'down'
      }
    },
    {
      type: 'status',
      at: '2026-03-17T03:15:00.000Z',
      status: 'down',
      reason: 'Ping failed: 100% packet loss'
    }
  );

  assert.match(message, /^🔴 \*DOWN\* Gateway/);
  assert.match(message, /\*Host:\* 203\.0\.113\.10/);
  assert.match(message, /\*Down at:\*/);
  assert.match(message, /203.0.113.10/);
});

test('recovery alert includes down and up timestamps', () => {
  const message = buildAlertMessage(
    {
      name: 'Gateway',
      checkType: 'ping',
      host: '203.0.113.10',
      url: '',
      runtime: {
        status: 'up'
      }
    },
    {
      type: 'recovery',
      at: '2026-03-17T03:20:00.000Z',
      downAt: '2026-03-17T03:00:00.000Z',
      durationSeconds: 1200
    }
  );

  assert.match(message, /^🟢 \*UP\* Gateway/);
  assert.match(message, /\*Host:\* 203\.0\.113\.10/);
  assert.match(message, /\*Down at:\*/);
  assert.match(message, /\*Up as of:\*/);
});
