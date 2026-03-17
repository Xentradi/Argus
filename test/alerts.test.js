const assert = require('node:assert/strict');
const { test } = require('node:test');

const config = require('../src/config');
const { buildWebhookBody } = require('../src/alerts');

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
