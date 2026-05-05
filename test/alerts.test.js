const assert = require('node:assert/strict');
const { test } = require('node:test');
const axios = require('axios');

const config = require('../src/config');
const { buildWebhookBody, buildAlertMessage } = require('../src/alerts');
const {
  buildAlertLines,
  buildWebhookBodyWithAlert,
  formatDuration,
  formatAlertTimestamp
} = require('../src/alerts/presentation');
const { sendWebhookAlert } = require('../src/alerts/transport');

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

test('formatDuration renders compact human readable durations', () => {
  assert.equal(formatDuration(59), '59s');
  assert.equal(formatDuration(61), '1m 1s');
  assert.equal(formatDuration(3661), '1h 1m 1s');
});

test('formatAlertTimestamp falls back on invalid timestamps', () => {
  assert.equal(formatAlertTimestamp('not-a-date'), 'not-a-date');
});

test('buildAlertLines includes host and error details for down alerts', () => {
  const lines = buildAlertLines(
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
      type: 'down',
      at: '2026-03-17T03:15:00.000Z',
      status: 'down',
      reason: 'Ping failed: 100% packet loss'
    },
    {
      emoji: '🔴',
      statusLabel: 'DOWN',
      timeLabel: 'Down at'
    }
  );

  assert.equal(lines[0], '🔴 *DOWN* Gateway');
  assert.equal(lines[1], '*Host:* 203.0.113.10');
  assert.match(lines.join('\n'), /Ping failed/);
});

test('buildWebhookBodyWithAlert preserves transport-specific payloads', () => {
  const body = buildWebhookBodyWithAlert(
    'discord',
    'ignored',
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
      type: 'down',
      at: '2026-03-17T03:15:00.000Z',
      status: 'down',
      reason: 'Ping failed: 100% packet loss'
    }
  );

  assert.equal(body.username, config.webhookDisplayName);
  assert.equal(Array.isArray(body.embeds), true);
  assert.match(body.embeds[0].title, /DOWN/);
});

test('sendWebhookAlert skips delivery when webhook URL is missing', async () => {
  const result = await sendWebhookAlert(
    {
      webhookUrl: '',
      webhookType: 'slack'
    },
    {
      type: 'status',
      at: '2026-03-17T03:15:00.000Z'
    }
  );

  assert.equal(result.ok, false);
  assert.equal(result.skipped, true);
  assert.match(result.error, /No webhook URL/i);
});

test('sendWebhookAlert posts payload and reports success', async () => {
  const originalPost = axios.post;
  const calls = [];
  axios.post = async (...args) => {
    calls.push(args);
    return { status: 204 };
  };

  try {
    const result = await sendWebhookAlert(
      {
        webhookUrl: 'https://example.invalid/webhook',
        webhookType: 'slack',
        name: 'Gateway',
        checkType: 'ping',
        host: '203.0.113.10',
        runtime: {
          status: 'down'
        }
      },
      {
        type: 'down',
        at: '2026-03-17T03:15:00.000Z',
        reason: 'Ping failed: 100% packet loss'
      }
    );

    assert.equal(result.ok, true);
    assert.equal(result.skipped, false);
    assert.equal(calls.length, 1);
    assert.equal(calls[0][0], 'https://example.invalid/webhook');
    assert.equal(calls[0][1].username, config.webhookDisplayName);
  } finally {
    axios.post = originalPost;
  }
});

test('sendWebhookAlert surfaces webhook delivery errors', async () => {
  const originalPost = axios.post;
  axios.post = async () => {
    throw new Error('boom');
  };

  try {
    const result = await sendWebhookAlert(
      {
        webhookUrl: 'https://example.invalid/webhook',
        webhookType: 'discord',
        name: 'Gateway',
        checkType: 'ping',
        host: '203.0.113.10',
        runtime: {
          status: 'down'
        }
      },
      {
        type: 'down',
        at: '2026-03-17T03:15:00.000Z',
        reason: 'Ping failed: 100% packet loss'
      }
    );

    assert.equal(result.ok, false);
    assert.equal(result.skipped, false);
    assert.match(result.error, /boom/);
  } finally {
    axios.post = originalPost;
  }
});
