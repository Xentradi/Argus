const axios = require('axios');
const {
  buildAlertMessage,
  buildWebhookBodyWithAlert
} = require('./presentation');

async function sendWebhookAlert(monitor, payload) {
  if (String(process.env.ALERTS_ENABLED || 'true').toLowerCase() === 'false') {
    return {
      ok: false,
      skipped: true,
      error: 'Outbound alerts are temporarily disabled'
    };
  }

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
  sendWebhookAlert
};
