const path = require('path');

function parseIntEnv(name, fallback, min, max) {
  const raw = process.env[name];
  if (raw === undefined) {
    return fallback;
  }

  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value)) {
    return fallback;
  }

  if (min !== undefined && value < min) {
    return min;
  }

  if (max !== undefined && value > max) {
    return max;
  }

  return value;
}

function trimTrailingSlash(value) {
  return String(value || '').replace(/\/+$/, '');
}

const port = parseIntEnv('PORT', 3000, 1, 65535);
const webhookPublicBaseUrl = trimTrailingSlash(
  process.env.WEBHOOK_PUBLIC_BASE_URL || process.env.APP_PUBLIC_URL || `http://127.0.0.1:${port}`
);
const webhookIconPath = process.env.WEBHOOK_ICON_PATH || '/img/argus.jpg';
const webhookIconUrl =
  process.env.WEBHOOK_ICON_URL ||
  (process.env.WEBHOOK_PUBLIC_BASE_URL || process.env.APP_PUBLIC_URL
    ? `${webhookPublicBaseUrl}${webhookIconPath}`
    : '');

module.exports = {
  appName: process.env.APP_NAME || 'Argus',
  port,
  dbFile: process.env.DB_FILE || path.join(process.cwd(), 'data', 'argus.db'),
  normalIntervalMs: parseIntEnv('NORMAL_INTERVAL_MS', 60_000, 1_000, 3_600_000),
  downIntervalMs: parseIntEnv('DOWN_INTERVAL_MS', 15_000, 1_000, 3_600_000),
  confirmationRetries: parseIntEnv('CONFIRMATION_RETRIES', 3, 1, 10),
  confirmationRetryIntervalMs: parseIntEnv('CONFIRMATION_RETRY_INTERVAL_MS', 5_000, 1_000, 60_000),
  defaultTimeoutMs: parseIntEnv('DEFAULT_TIMEOUT_MS', 10_000, 1_000, 120_000),
  minTimeoutMs: 1_000,
  maxTimeoutMs: 120_000,
  retentionDays: parseIntEnv('RETENTION_DAYS', 1095, 30, 5000),
  webhookDisplayName: process.env.WEBHOOK_DISPLAY_NAME || 'Argus',
  webhookIconUrl
};
