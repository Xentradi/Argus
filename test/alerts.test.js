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
      lastCheckAt: '2026-03-17T03:14:45.000Z',
      reason: 'Ping failed: 100% packet loss',
      trigger: 'manual monitor alert'
    }
  );

  assert.match(message, /\[STATUS\] Gateway/);
  assert.match(message, /Current status: DOWN/);
  assert.match(message, /Last check: 2026-03-17T03:14:45.000Z/);
  assert.match(message, /Triggered by: manual monitor alert/);
});
