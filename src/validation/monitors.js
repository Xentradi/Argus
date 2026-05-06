function createMonitorValidation({ store, config, clampNumber, isLikelyUrl, normalizeUrl, safeLower }) {
  function parseOptionalMs(value, min, max) {
    if (value === undefined || value === null) {
      return null;
    }

    const trimmed = String(value).trim();
    if (!trimmed) {
      return null;
    }

    return clampNumber(trimmed, min, max, null);
  }

  function parseMonitorForm(body, existing = null, userId = null) {
    const errors = [];
    const input = body && typeof body === 'object' ? body : {};

    const checkType = safeLower(input.checkType);
    const name = String(input.name || '').trim();
    const groupId = String(input.groupId || '').trim() || null;
    const host = String(input.host || '').trim();
    const url = normalizeUrl(input.url);
    const keyword = String(input.keyword || '').trim();

    if (!name) {
      errors.push('Name is required.');
    }

    if (!['ping', 'http', 'keyword'].includes(checkType)) {
      errors.push('Check type must be ping, http, or keyword.');
    }

    if (checkType === 'ping') {
      if (!host) {
        errors.push('Host is required for ping checks.');
      }
    } else if (!url || !isLikelyUrl(url)) {
      errors.push('A valid http(s) URL is required for HTTP and keyword checks.');
    }

    if (checkType === 'keyword' && !keyword) {
      errors.push('Keyword is required for keyword checks.');
    }

    let selectedGroup = null;
    if (groupId) {
      selectedGroup = store.getGroupById(groupId, userId);
      if (!selectedGroup) {
        errors.push('Selected group was not found.');
      }
    }

    let webhookType = '';
    let webhookUrl = '';
    let groupName = '';

    if (selectedGroup) {
      webhookType = selectedGroup.webhookType;
      webhookUrl = selectedGroup.webhookUrl;
      groupName = selectedGroup.name;
    } else {
      webhookType = safeLower(input.webhookType);
      if (!['slack', 'discord'].includes(webhookType)) {
        errors.push('Webhook type must be Slack or Discord.');
      }

      webhookUrl = normalizeUrl(input.webhookUrl);
      if (!webhookUrl || !isLikelyUrl(webhookUrl)) {
        errors.push('A valid webhook URL is required for ungrouped monitors.');
      }
    }

    const timeoutMs = clampNumber(
      input.timeoutMs,
      config.minTimeoutMs,
      config.maxTimeoutMs,
      existing ? existing.timeoutMs : config.defaultTimeoutMs
    );
    const minDowntimeMs = parseOptionalMs(input.minDowntimeMs, 1_000, 3_600_000);
    const alertCooldownMs = parseOptionalMs(input.alertCooldownMs, 1_000, 3_600_000);

    const monitorPayload = {
      name,
      groupId,
      groupName,
      checkType,
      host,
      url,
      keyword,
      keywordCaseSensitive: input.keywordCaseSensitive === 'on',
      httpStatusMode: input.httpStatusMode === '200' ? '200' : '2xx',
      tlsErrorAsFailure: input.tlsErrorAsFailure !== 'false',
      webhookType,
      webhookUrl,
      timeoutMs,
      minDowntimeMs,
      alertCooldownMs,
      active: input.active === 'on'
    };

    return {
      errors,
      monitorPayload
    };
  }

  function monitorToFormBody(monitor) {
    return {
      name: monitor.name,
      groupId: monitor.groupId || '',
      checkType: monitor.checkType,
      host: monitor.host || '',
      url: monitor.url || '',
      keyword: monitor.keyword || '',
      keywordCaseSensitive: monitor.keywordCaseSensitive ? 'on' : '',
      httpStatusMode: monitor.httpStatusMode || '2xx',
      tlsErrorAsFailure: monitor.tlsErrorAsFailure !== false ? 'true' : 'false',
      webhookType: monitor.webhookType || 'slack',
      webhookUrl: monitor.webhookUrl || '',
      timeoutMs: monitor.timeoutMs,
      minDowntimeMs:
        monitor.minDowntimeMs === null || monitor.minDowntimeMs === undefined ? '' : monitor.minDowntimeMs,
      alertCooldownMs:
        monitor.alertCooldownMs === null || monitor.alertCooldownMs === undefined ? '' : monitor.alertCooldownMs,
      active: monitor.active ? 'on' : ''
    };
  }

  function normalizeApiMonitorBody(body, existing = null) {
    const normalized = existing ? monitorToFormBody(existing) : {};
    const input = body && typeof body === 'object' ? body : {};

    if (input.name !== undefined) {
      normalized.name = input.name;
    }
    if (input.groupId !== undefined) {
      normalized.groupId = input.groupId === null ? '' : input.groupId;
    }
    if (input.checkType !== undefined) {
      normalized.checkType = input.checkType;
    }
    if (input.host !== undefined) {
      normalized.host = input.host;
    }
    if (input.url !== undefined) {
      normalized.url = input.url;
    }
    if (input.keyword !== undefined) {
      normalized.keyword = input.keyword;
    }
    if (input.keywordCaseSensitive !== undefined) {
      normalized.keywordCaseSensitive = input.keywordCaseSensitive ? 'on' : '';
    }
    if (input.httpStatusMode !== undefined) {
      normalized.httpStatusMode = input.httpStatusMode;
    }
    if (input.tlsErrorAsFailure !== undefined) {
      normalized.tlsErrorAsFailure = input.tlsErrorAsFailure ? 'true' : 'false';
    }
    if (input.webhookType !== undefined) {
      normalized.webhookType = input.webhookType;
    }
    if (input.webhookUrl !== undefined) {
      normalized.webhookUrl = input.webhookUrl;
    }
    if (input.timeoutMs !== undefined) {
      normalized.timeoutMs = input.timeoutMs;
    }
    if (input.minDowntimeMs !== undefined) {
      normalized.minDowntimeMs = input.minDowntimeMs;
    }
    if (input.alertCooldownMs !== undefined) {
      normalized.alertCooldownMs = input.alertCooldownMs;
    }
    if (input.active !== undefined) {
      normalized.active = input.active ? 'on' : '';
    }

    return normalized;
  }

  return {
    parseMonitorForm,
    monitorToFormBody,
    normalizeApiMonitorBody
  };
}

module.exports = {
  createMonitorValidation
};
