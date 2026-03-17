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
  return buildAlertLines(monitor, payload, presentation).join('\n');
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
      title: `🔴 DOWN - ${monitor.name}`,
      colorHex: '#dc2626',
      statusLabel: 'DOWN',
      timeLabel: 'Down at',
      emoji: '🔴'
    };
  }

  if (payload.type === 'recovery') {
    return {
      title: '🟢 UP',
      colorHex: '#16a34a',
      statusLabel: 'UP',
      timeLabel: 'Up as of',
      emoji: '🟢'
    };
  }

  if (status === 'down') {
    return {
      title: `🔴 DOWN - ${monitor.name}`,
      colorHex: '#dc2626',
      statusLabel: 'DOWN',
      timeLabel: 'Down at',
      emoji: '🔴'
    };
  }

  if (status === 'up') {
    return {
      title: `🟢 UP - ${monitor.name}`,
      colorHex: '#16a34a',
      statusLabel: 'UP',
      timeLabel: 'Up as of',
      emoji: '🟢'
    };
  }

  return {
    title: `🟡 STATUS - ${monitor.name}`,
    colorHex: '#64748b',
    statusLabel: (status || 'unknown').toUpperCase(),
    timeLabel: 'Status as of',
    emoji: '🟡'
  };
}

function buildAlertLines(monitor, payload, presentation) {
  const formattedTime = formatAlertTimestamp(payload.at);
  const target = monitorTarget(monitor);
  const lines = [
    `${presentation.emoji} *${presentation.statusLabel}* ${monitor.name}`,
    `*Host:* ${target || '-'}`,
    `*${presentation.timeLabel}:* ${formattedTime}`
  ];

  if (payload.type === 'recovery') {
    lines.push(`*Downtime:* ${formatDuration(payload.durationSeconds)}`);
  }

  if (payload.reason && presentation.statusLabel === 'DOWN') {
    lines.push(`*Error:* ${payload.reason}`);
  }

  return lines;
}

function buildWebhookBody(webhookType, text) {
  return buildWebhookBodyWithAlert(webhookType, text, null, null);
}

function buildWebhookBodyWithAlert(webhookType, text, monitor, payload) {
  const common = {
    username: config.webhookDisplayName
  };

  const presentation = monitor && payload ? resolveAlertPresentation(monitor, payload) : null;
  const lines = monitor && payload ? buildAlertLines(monitor, payload, presentation) : [];
  const detailText = lines.slice(1).join('\n');

  if (webhookType === 'discord') {
    const body = { ...common };

    if (presentation) {
      body.embeds = [
        {
          title: presentation.title,
          color: hexToDiscordColor(presentation.colorHex),
          description: detailText,
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
    text: presentation ? lines[0] : text,
    ...common
  };

  if (presentation) {
    body.attachments = [
      {
        color: presentation.colorHex,
        text: detailText,
        mrkdwn_in: ['text'],
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
