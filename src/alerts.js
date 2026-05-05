const {
  formatDuration,
  formatAlertTimestamp,
  buildAlertMessage,
  buildWebhookBody
} = require('./alerts/presentation');
const { sendWebhookAlert } = require('./alerts/transport');

module.exports = {
  sendWebhookAlert,
  formatDuration,
  buildWebhookBody,
  buildAlertMessage,
  formatAlertTimestamp
};
