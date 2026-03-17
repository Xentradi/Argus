const axios = require('axios');
const config = require('./config');

function formatDuration(totalSeconds) {
  if (!Number.isFinite(totalSeconds) || totalSeconds < 0) {
    return 'unknown';
  }

  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  const parts = [];
  if (hours > 0) {
    parts.push(`${hours}h`);
  }
  if (minutes > 0 || hours > 0) {
    parts.push(`${minutes}m`);
  }
  parts.push(`${seconds}s`);

  return parts.join(' ');
}

function buildAlertMessage(monitor, payload) {
  const lines = [];

  if (payload.type === 'down') {
    lines.push(`[DOWN] ${monitor.name}`);
    lines.push(`Check type: ${monitor.checkType}`);
    lines.push(`Target: ${monitor.checkType === 'ping' ? monitor.host : monitor.url}`);
    lines.push(`Time: ${payload.at}`);
    lines.push(`Reason: ${payload.reason || 'Unknown failure'}`);
  } else if (payload.type === 'recovery') {
    lines.push(`[RECOVERY] ${monitor.name}`);
    lines.push(`Check type: ${monitor.checkType}`);
    lines.push(`Target: ${monitor.checkType === 'ping' ? monitor.host : monitor.url}`);
    lines.push(`Time: ${payload.at}`);
    lines.push(`Downtime: ${formatDuration(payload.durationSeconds)}`);
    lines.push(`Recovery check: ${payload.reason || 'Confirmed healthy'}`);
  } else {
    lines.push(`[STATUS] ${monitor.name}`);
    lines.push(`Check type: ${monitor.checkType}`);
    lines.push(`Target: ${monitor.checkType === 'ping' ? monitor.host : monitor.url}`);
    lines.push(`Time: ${payload.at}`);
    lines.push(`Current status: ${String(payload.status || monitor.runtime?.status || 'unknown').toUpperCase()}`);

    if (payload.lastCheckAt) {
      lines.push(`Last check: ${payload.lastCheckAt}`);
    }

    if (payload.reason) {
      lines.push(`Last error: ${payload.reason}`);
    }

    lines.push(`Triggered by: ${payload.trigger || 'manual'}`);
  }

  return lines.join('\n');
}

async function postWebhook(webhookType, webhookUrl, text) {
  const body = buildWebhookBody(webhookType, text);

  await axios.post(webhookUrl, body, {
    timeout: 10_000,
    headers: {
      'content-type': 'application/json'
    }
  });
}

function buildWebhookBody(webhookType, text) {
  const common = {
    username: config.webhookDisplayName
  };

  if (webhookType === 'discord') {
    const body = {
      content: text,
      ...common
    };

    if (config.webhookIconUrl) {
      body.avatar_url = config.webhookIconUrl;
    }

    return body;
  }

  const body = {
    text,
    ...common
  };

  if (config.webhookIconUrl) {
    body.icon_url = config.webhookIconUrl;
  }

  return body;
}

async function sendWebhookAlert(monitor, payload) {
  if (!monitor.webhookUrl) {
    return {
      ok: false,
      skipped: true,
      error: 'No webhook URL configured'
    };
  }

  const webhookType = monitor.webhookType === 'discord' ? 'discord' : 'slack';
  const message = buildAlertMessage(monitor, payload);

  try {
    await postWebhook(webhookType, monitor.webhookUrl, message);
    return {
      ok: true,
      skipped: false,
      message
    };
  } catch (error) {
    return {
      ok: false,
      skipped: false,
      error: error.message || 'Webhook delivery failed',
      message
    };
  }
}

module.exports = {
  sendWebhookAlert,
  formatDuration,
  buildWebhookBody,
  buildAlertMessage
};
