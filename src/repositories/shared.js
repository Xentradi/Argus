const crypto = require('crypto');

function nowIso() {
  return new Date().toISOString();
}

function toIntegerBoolean(value) {
  return value ? 1 : 0;
}

function fromIntegerBoolean(value) {
  return Number(value) === 1;
}

function resolveOwnerUserId(db, candidateUserId) {
  const trimmed = String(candidateUserId || '').trim();
  if (trimmed) {
    return trimmed;
  }

  const row = db.prepare('SELECT id FROM users ORDER BY datetime(created_at) ASC LIMIT 1').get();
  return row ? row.id : null;
}

function hashApiKeySecret(secret, saltBase64) {
  const salt = Buffer.from(String(saltBase64 || ''), 'base64');
  return crypto.pbkdf2Sync(String(secret || ''), salt, 120000, 32, 'sha256').toString('base64');
}

function rowToGroup(row) {
  return {
    id: row.id,
    userId: row.user_id || null,
    name: row.name,
    webhookType: row.webhook_type,
    webhookUrl: row.webhook_url,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function rowToStatusPage(row) {
  return {
    id: row.id,
    userId: row.user_id || null,
    name: row.name,
    slug: row.slug,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function rowToMonitor(row) {
  return {
    id: row.id,
    userId: row.user_id || null,
    name: row.name,
    groupId: row.group_id || null,
    groupName: row.group_name || '',
    sortOrder: Number.isFinite(Number(row.sort_order)) ? Number(row.sort_order) : 0,
    checkType: row.check_type,
    host: row.host,
    url: row.url,
    keyword: row.keyword,
    keywordCaseSensitive: fromIntegerBoolean(row.keyword_case_sensitive),
    httpStatusMode: row.http_status_mode,
    tlsErrorAsFailure: fromIntegerBoolean(row.tls_error_as_failure),
    webhookType: row.webhook_type,
    webhookUrl: row.webhook_url,
    timeoutMs: row.timeout_ms,
    minDowntimeMs: row.min_downtime_ms === null || row.min_downtime_ms === undefined ? null : Number(row.min_downtime_ms),
    alertCooldownMs: row.alert_cooldown_ms === null || row.alert_cooldown_ms === undefined ? null : Number(row.alert_cooldown_ms),
    active: fromIntegerBoolean(row.active),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    runtime: {
      status: row.status,
      lastCheckAt: row.last_check_at,
      firstSuccessAt: row.first_success_at,
      lastSuccessAt: row.last_success_at,
      lastFailureAt: row.last_failure_at,
      lastError: row.last_error,
      lastResponseMs: row.last_response_ms,
      lastHttpStatus: row.last_http_status,
      lastKeywordMatched:
        row.last_keyword_matched === null || row.last_keyword_matched === undefined
          ? null
          : fromIntegerBoolean(row.last_keyword_matched),
      lastTlsError: fromIntegerBoolean(row.last_tls_error),
      lastAlertDownAt: row.last_alert_down_at,
      nextCheckAt: row.next_check_at
    }
  };
}

function rowToIncident(row) {
  return {
    id: row.id,
    userId: row.user_id || null,
    monitorId: row.monitor_id,
    monitorName: row.monitor_name,
    startedAt: row.started_at,
    endedAt: row.ended_at,
    durationSeconds: row.duration_seconds,
    downReason: row.down_reason,
    recoveryReason: row.recovery_reason,
    alertedAt: row.alerted_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function rowToEvent(row) {
  return {
    id: row.id,
    userId: row.user_id || null,
    monitorId: row.monitor_id,
    monitorName: row.monitor_name,
    eventType: row.event_type,
    message: row.message,
    details: row.details_json ? JSON.parse(row.details_json) : null,
    createdAt: row.created_at
  };
}

module.exports = {
  nowIso,
  toIntegerBoolean,
  fromIntegerBoolean,
  resolveOwnerUserId,
  hashApiKeySecret,
  rowToGroup,
  rowToStatusPage,
  rowToMonitor,
  rowToIncident,
  rowToEvent
};
