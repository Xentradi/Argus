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

function formatAlertTimestamp(isoTime) {
  const raw = isoTime || new Date().toISOString();
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    return raw;
  }

  try {
    return new Intl.DateTimeFormat('en-US', {
      timeZone: config.alertTimezone,
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: 'numeric',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
      timeZoneName: 'short'
    }).format(parsed);
  } catch (_error) {
    return parsed.toISOString();
  }
}

function hexToDiscordColor(hex) {
  return Number.parseInt(String(hex || '').replace('#', ''), 16) || 0x3b82f6;
}

function resolveAlertPresentation(monitor, payload) {
  const status = String(payload.status || monitor.runtime?.status || '').toLowerCase();

  if (payload.type === 'down') {
    return {
      title: `DOWN • ${monitor.name}`,
      colorHex: '#dc2626',
      statusLabel: 'DOWN'
    };
  }

  if (payload.type === 'recovery') {
    return {
      title: `RECOVERY • ${monitor.name}`,
      colorHex: '#16a34a',
      statusLabel: 'UP'
    };
  }

  if (status === 'down') {
    return {
      title: `STATUS • ${monitor.name}`,
      colorHex: '#dc2626',
      statusLabel: 'DOWN'
    };
  }

  if (status === 'up') {
    return {
      title: `STATUS • ${monitor.name}`,
      colorHex: '#16a34a',
      statusLabel: 'UP'
    };
  }

  return {
    title: `STATUS • ${monitor.name}`,
    colorHex: '#64748b',
    statusLabel: (status || 'unknown').toUpperCase()
  };
}

function buildAlertFields(monitor, payload) {
  const formattedTime = formatAlertTimestamp(payload.at);
  const target = monitor.checkType === 'ping' ? monitor.host : monitor.url;
  const presentation = resolveAlertPresentation(monitor, payload);
  const fields = [
    { name: 'Status', value: presentation.statusLabel, inline: true },
    { name: 'Check Type', value: monitor.checkType, inline: true },
    { name: 'Target', value: target || '-', inline: false },
    { name: 'Time', value: formattedTime, inline: false }
  ];

  if (payload.type === 'recovery') {
    fields.push({
      name: 'Downtime',
      value: formatDuration(payload.durationSeconds),
      inline: true
    });
  }

  if (payload.lastCheckAt) {
    fields.push({
      name: 'Last Check',
      value: formatAlertTimestamp(payload.lastCheckAt),
      inline: false
    });
  }

  if (payload.reason) {
    fields.push({
      name: payload.type === 'down' ? 'Reason' : 'Details',
      value: payload.reason,
      inline: false
    });
  }

  if (payload.trigger) {
    fields.push({
      name: 'Triggered By',
      value: payload.trigger,
      inline: true
    });
  }

  return fields;
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
  return buildWebhookBodyWithAlert(webhookType, text, null, null);
}

function buildWebhookBodyWithAlert(webhookType, text, monitor, payload) {
  const common = {
    username: config.webhookDisplayName
  };

  const presentation = monitor && payload ? resolveAlertPresentation(monitor, payload) : null;
  const fields = monitor && payload ? buildAlertFields(monitor, payload) : [];

  if (webhookType === 'discord') {
    const body = {
      content: text,
      ...common
    };

    if (presentation) {
      body.embeds = [
        {
          title: presentation.title,
          color: hexToDiscordColor(presentation.colorHex),
          fields: fields.map((field) => ({
            name: field.name,
            value: field.value || '-',
            inline: Boolean(field.inline)
          })),
          footer: {
            text: `${config.appName} • ${config.alertTimezone}`
          }
        }
      ];
    }

    if (config.webhookIconUrl) {
      body.avatar_url = config.webhookIconUrl;
    }

    return body;
  }

  const body = {
    text,
    ...common
  };

  if (presentation) {
    body.attachments = [
      {
        color: presentation.colorHex,
        title: presentation.title,
        fields: fields.map((field) => ({
          title: field.name,
          value: field.value || '-',
          short: Boolean(field.inline)
        })),
        footer: `${config.appName} • ${config.alertTimezone}`
      }
    ];
  }

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
  const body = buildWebhookBodyWithAlert(webhookType, message, monitor, payload);

  try {
    await axios.post(monitor.webhookUrl, body, {
      timeout: 10_000,
      headers: {
        'content-type': 'application/json'
      }
    });
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
  buildAlertMessage,
  formatAlertTimestamp
};
