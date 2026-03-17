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

function monitorTarget(monitor) {
  return monitor.checkType === 'ping' ? monitor.host : monitor.url;
}

function buildAlertMessage(monitor, payload) {
  const presentation = resolveAlertPresentation(monitor, payload);
  const at = formatAlertTimestamp(payload.at);
  const target = monitorTarget(monitor) || '-';
  return `${presentation.statusLabel} - ${monitor.name} - ${presentation.timeLabel} ${at} - ${target}`;
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
      title: `*DOWN* - ${monitor.name}`,
      colorHex: '#dc2626',
      statusLabel: 'DOWN',
      timeLabel: 'Down at'
    };
  }

  if (payload.type === 'recovery') {
    return {
      title: `*UP* - ${monitor.name}`,
      colorHex: '#16a34a',
      statusLabel: 'UP',
      timeLabel: 'Up as of'
    };
  }

  if (status === 'down') {
    return {
      title: `*DOWN* - ${monitor.name}`,
      colorHex: '#dc2626',
      statusLabel: 'DOWN',
      timeLabel: 'Down at'
    };
  }

  if (status === 'up') {
    return {
      title: `*UP* - ${monitor.name}`,
      colorHex: '#16a34a',
      statusLabel: 'UP',
      timeLabel: 'Up as of'
    };
  }

  return {
    title: `*STATUS* - ${monitor.name}`,
    colorHex: '#64748b',
    statusLabel: (status || 'unknown').toUpperCase(),
    timeLabel: 'Status as of'
  };
}

function buildAlertFields(monitor, payload) {
  const formattedTime = formatAlertTimestamp(payload.at);
  const target = monitorTarget(monitor);
  const presentation = resolveAlertPresentation(monitor, payload);
  const fields = [
    { name: 'Target', value: target || '-', inline: false },
    { name: presentation.timeLabel, value: formattedTime, inline: false }
  ];

  if (payload.type === 'recovery') {
    fields.push({
      name: 'Downtime',
      value: formatDuration(payload.durationSeconds),
      inline: true
    });
  }

  if (payload.reason) {
    fields.push({
      name: payload.type === 'down' ? 'Error' : 'Details',
      value: payload.reason,
      inline: false
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
    const body = { ...common };

    if (presentation) {
      body.embeds = [
        {
          title: presentation.title,
          color: hexToDiscordColor(presentation.colorHex),
          description: `**${presentation.statusLabel}**`,
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
    } else {
      body.content = text;
    }

    if (config.webhookIconUrl) {
      body.avatar_url = config.webhookIconUrl;
    }

    return body;
  }

  const body = {
    text: presentation ? `${presentation.statusLabel}: ${monitor.name}` : text,
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
