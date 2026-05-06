function createGroupValidation({ normalizeUrl, safeLower, isLikelyUrl }) {
  function parseGroupForm(body) {
    const errors = [];
    const input = body && typeof body === 'object' ? body : {};
    const name = String(input.name || '').trim();
    const webhookType = safeLower(input.webhookType);
    const webhookUrl = normalizeUrl(input.webhookUrl);

    if (!name) {
      errors.push('Group name is required.');
    }

    if (name.length > 120) {
      errors.push('Group name must be 120 characters or less.');
    }

    if (!['slack', 'discord'].includes(webhookType)) {
      errors.push('Webhook type must be Slack or Discord.');
    }

    if (!webhookUrl || !isLikelyUrl(webhookUrl)) {
      errors.push('A valid webhook URL is required.');
    }

    return {
      errors,
      payload: {
        name,
        webhookType,
        webhookUrl
      }
    };
  }

  return {
    parseGroupForm
  };
}

module.exports = {
  createGroupValidation
};
