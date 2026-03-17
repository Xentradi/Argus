function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function clampNumber(value, min, max, fallback) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }

  if (parsed < min) {
    return min;
  }

  if (parsed > max) {
    return max;
  }

  return parsed;
}

function normalizeUrl(url) {
  if (!url) {
    return '';
  }

  return String(url).trim();
}

function safeLower(value) {
  return String(value || '').toLowerCase();
}

function isLikelyUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch (error) {
    return false;
  }
}

function toAbsoluteIsoDate(value) {
  if (!value) {
    return null;
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString();
}

module.exports = {
  sleep,
  clampNumber,
  normalizeUrl,
  safeLower,
  isLikelyUrl,
  toAbsoluteIsoDate
};
