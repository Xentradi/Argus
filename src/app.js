const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const helmet = require('helmet');
const path = require('path');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const config = require('./config');
const { DataStore } = require('./store');
const { MonitorEngine } = require('./monitorEngine');
const { sendWebhookAlert } = require('./alerts');
const { clampNumber, isLikelyUrl, normalizeUrl, safeLower } = require('./utils');

const app = express();
const store = new DataStore(config.dbFile, config.retentionDays);

const engine = new MonitorEngine({
  store,
  normalIntervalMs: config.normalIntervalMs,
  downIntervalMs: config.downIntervalMs,
  confirmationRetries: config.confirmationRetries,
  confirmationRetryIntervalMs: config.confirmationRetryIntervalMs,
  logger: console
});

engine.start();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: '1mb' }));
app.use('/public', express.static(path.join(__dirname, '..', 'public')));
app.use('/img', express.static(path.join(__dirname, '..', 'public', 'img')));

// Backward-compatible icon URL used in many webhook configs.
app.get('/img/argus.jpg', (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'img', 'argus-logo.png'));
});

app.get('/favicon.ico', (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'img', 'favicon.ico'));
});

const sessionDbDir = path.dirname(config.dbFile);
const sessionDbFile = process.env.SESSION_DB_FILE || 'argus-sessions.sqlite';
const sessionCookieName = process.env.NODE_ENV === 'production' ? '__Host-argus_sid' : 'argus_sid';
const sessionCookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
  maxAge: 24 * 60 * 60 * 1000
};

app.use(
  session({
    store: new SQLiteStore({
      dir: sessionDbDir,
      db: sessionDbFile,
      table: 'sessions'
    }),
    name: sessionCookieName,
    secret: process.env.SESSION_SECRET || store.getSessionSecret(),
    resave: false,
    saveUninitialized: false,
    cookie: sessionCookieOptions
  })
);

function setFlash(req, type, message) {
  req.session.flash = {
    type,
    message
  };
}

function clearSetupSecret(req) {
  delete req.session.setupTotpSecret;
  delete req.session.setupTotpOtpauth;
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

function asyncHandler(fn) {
  return function wrapped(req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

function requireAuth(req, res, next) {
  if (!store.hasUsers()) {
    res.redirect('/setup');
    return;
  }

  if (!req.session.authenticatedUserId) {
    res.redirect('/login');
    return;
  }

  const user = store.findUserById(req.session.authenticatedUserId);
  if (!user) {
    req.session.authenticatedUserId = null;
    res.redirect('/login');
    return;
  }

  res.locals.currentUser = {
    id: user.id,
    username: user.username
  };
  req.authenticatedUser = user;

  next();
}

const apiRateWindowMs = 60 * 1000;
const apiRateMaxRequests = 240;
const apiRateBuckets = new Map();

function rateLimitApiKey(keyId) {
  const now = Date.now();
  const existing = apiRateBuckets.get(keyId);
  if (!existing || now - existing.windowStartMs >= apiRateWindowMs) {
    apiRateBuckets.set(keyId, {
      windowStartMs: now,
      count: 1
    });
    return true;
  }

  if (existing.count >= apiRateMaxRequests) {
    return false;
  }

  existing.count += 1;
  return true;
}

function requireApiKey(req, res, next) {
  const authorization = String(req.headers.authorization || '');
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    res.status(401).json({
      error: 'Missing API key bearer token.'
    });
    return;
  }

  const auth = store.authenticateApiKey(match[1]);
  if (!auth) {
    res.status(401).json({
      error: 'Invalid API key.'
    });
    return;
  }

  if (!rateLimitApiKey(auth.id)) {
    res.status(429).json({
      error: 'API rate limit exceeded. Try again in a minute.'
    });
    return;
  }

  const user = store.findUserById(auth.userId);
  if (!user) {
    res.status(401).json({
      error: 'API key owner was not found.'
    });
    return;
  }

  req.apiAuth = auth;
  req.apiUser = user;
  next();
}

function monitorTarget(monitor) {
  return monitor.checkType === 'ping' ? monitor.host : monitor.url;
}

function elapsedSecondsSince(isoDate, nowMs = Date.now()) {
  const startedMs = new Date(isoDate).getTime();
  if (!Number.isFinite(startedMs)) {
    return null;
  }

  if (nowMs < startedMs) {
    return 0;
  }

  return Math.round((nowMs - startedMs) / 1000);
}

function buildDashboardSnapshot({ userId = null, eventsPage = 1, includeEvents = true, includeIncidents = true } = {}) {
  const monitors = store.listMonitors(userId);
  const groups = store.listGroups(userId);
  const groupsById = new Map(groups.map((group) => [group.id, group]));
  const openIncidentsByMonitorId = new Map(store.listOpenIncidents(userId).map((incident) => [incident.monitorId, incident]));
  const nowMs = Date.now();
  const groupedMap = new Map();
  const serializedMonitors = [];

  for (const monitor of monitors) {
    const effectiveGroup = monitor.groupId ? groupsById.get(monitor.groupId) : null;
    const bucketKey = effectiveGroup ? effectiveGroup.id : 'ungrouped';
    const bucketName = effectiveGroup ? effectiveGroup.name : 'Ungrouped';
    const status = monitor.runtime.status || 'unknown';
    const isPaused = !monitor.active;
    const statusClass = isPaused ? 'paused' : status;
    const hasUnconfirmedFailures = !isPaused && status === 'up' && Boolean(monitor.runtime.lastError);
    const displayStatus = isPaused ? 'paused' : hasUnconfirmedFailures ? 'up (confirming)' : status;
    const openIncident = openIncidentsByMonitorId.get(monitor.id) || null;
    const downSince = openIncident
      ? openIncident.startedAt
      : status === 'down'
        ? monitor.runtime.lastFailureAt || monitor.runtime.lastCheckAt || null
        : null;
    const outageSeconds = downSince ? elapsedSecondsSince(downSince, nowMs) : null;

    const dashboardMonitor = {
      id: monitor.id,
      name: monitor.name,
      groupId: effectiveGroup ? effectiveGroup.id : null,
      groupName: bucketName,
      sortOrder: monitor.sortOrder || 0,
      checkType: monitor.checkType,
      target: monitorTarget(monitor) || '-',
      active: monitor.active,
      statusClass,
      displayStatus,
      runtime: {
        status,
        lastCheckAt: monitor.runtime.lastCheckAt || null,
        nextCheckAt: monitor.runtime.nextCheckAt || null,
        lastError: monitor.runtime.lastError || null,
        lastResponseMs: monitor.runtime.lastResponseMs,
        lastHttpStatus: monitor.runtime.lastHttpStatus,
        lastKeywordMatched: monitor.runtime.lastKeywordMatched,
        lastFailureAt: monitor.runtime.lastFailureAt || null,
        lastSuccessAt: monitor.runtime.lastSuccessAt || null
      },
      hasUnconfirmedFailures,
      outage: {
        active: !isPaused && status === 'down',
        startedAt: downSince,
        durationSeconds: !isPaused && status === 'down' ? outageSeconds : null
      }
    };

    serializedMonitors.push(dashboardMonitor);

    if (!groupedMap.has(bucketKey)) {
      groupedMap.set(bucketKey, {
        groupId: effectiveGroup ? effectiveGroup.id : null,
        groupName: bucketName,
        monitors: []
      });
    }
    groupedMap.get(bucketKey).monitors.push(dashboardMonitor);
  }

  const groupedMonitors = Array.from(groupedMap.values())
    .sort((left, right) => {
      if (!left.groupId && right.groupId) {
        return 1;
      }
      if (left.groupId && !right.groupId) {
        return -1;
      }
      return left.groupName.localeCompare(right.groupName);
    })
    .map((group) => ({
      ...group,
      monitors: group.monitors
        .slice()
        .sort(
          (left, right) =>
            (left.sortOrder || 0) - (right.sortOrder || 0) || left.name.localeCompare(right.name)
        )
    }));

  const summary = {
    total: serializedMonitors.length,
    groups: groupedMonitors.length,
    up: serializedMonitors.filter((monitor) => monitor.statusClass === 'up').length,
    down: serializedMonitors.filter((monitor) => monitor.statusClass === 'down').length,
    unknown: serializedMonitors.filter((monitor) => monitor.statusClass === 'unknown' || monitor.statusClass === 'paused').length
  };

  const activeOutages = serializedMonitors
    .filter((monitor) => monitor.active && monitor.runtime.status === 'down')
    .map((monitor) => ({
      monitorId: monitor.id,
      monitorName: monitor.name,
      groupName: monitor.groupName,
      target: monitor.target,
      downSince: monitor.outage.startedAt,
      durationSeconds: monitor.outage.durationSeconds,
      reason: monitor.runtime.lastError || 'No failure details'
    }))
    .sort((left, right) => (right.durationSeconds || 0) - (left.durationSeconds || 0));

  const snapshot = {
    generatedAt: new Date(nowMs).toISOString(),
    summary,
    groupedMonitors,
    activeOutages
  };

  if (includeIncidents) {
    const incidents = store.listIncidents(250, userId).map((incident) => {
      if (incident.endedAt || !incident.startedAt) {
        return incident;
      }
      return {
        ...incident,
        durationSeconds: elapsedSecondsSince(incident.startedAt, nowMs)
      };
    });

    const incidentsByMonitor = {};
    for (const incident of incidents) {
      if (!incidentsByMonitor[incident.monitorId]) {
        incidentsByMonitor[incident.monitorId] = [];
      }

      if (incidentsByMonitor[incident.monitorId].length < 8) {
        incidentsByMonitor[incident.monitorId].push(incident);
      }
    }

    snapshot.incidents = incidents;
    snapshot.incidentsByMonitor = incidentsByMonitor;
  }

  if (includeEvents) {
    const requestedEventsPage = clampNumber(eventsPage, 1, 1000000, 1);
    const eventsPerPage = 20;
    const totalEvents = store.countEvents(userId);
    const totalEventPages = Math.max(1, Math.ceil(totalEvents / eventsPerPage));
    const safeEventsPage = Math.min(requestedEventsPage, totalEventPages);
    const eventsOffset = (safeEventsPage - 1) * eventsPerPage;

    snapshot.events = store.listEvents(eventsPerPage, eventsOffset, userId);
    const operationalEventTypes = new Set([
      'monitor_down',
      'monitor_recovered',
      'alert_down_sent',
      'alert_down_failed',
      'alert_recovery_sent',
      'alert_recovery_failed',
      'manual_alert_sent',
      'manual_alert_failed'
    ]);
    snapshot.operationalEvents = snapshot.events.filter((event) => operationalEventTypes.has(event.eventType));
    snapshot.eventPagination = {
      page: safeEventsPage,
      totalPages: totalEventPages,
      hasPrev: safeEventsPage > 1,
      hasNext: safeEventsPage < totalEventPages
    };
  }

  return snapshot;
}

async function sendManualStatusAlert(monitor, trigger) {
  return sendWebhookAlert(monitor, {
    type: 'status',
    at: new Date().toISOString(),
    status: monitor.runtime?.status || 'unknown',
    lastCheckAt: monitor.runtime?.lastCheckAt || null,
    reason: monitor.runtime?.lastError || null,
    trigger
  });
}

function parseMonitorForm(body, existing = null, userId = null) {
  const errors = [];

  const checkType = safeLower(body.checkType);
  const name = String(body.name || '').trim();
  const groupId = String(body.groupId || '').trim() || null;
  const host = String(body.host || '').trim();
  const url = normalizeUrl(body.url);
  const keyword = String(body.keyword || '').trim();

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
  } else {
    if (!url || !isLikelyUrl(url)) {
      errors.push('A valid http(s) URL is required for HTTP and keyword checks.');
    }
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
    webhookType = safeLower(body.webhookType);
    if (!['slack', 'discord'].includes(webhookType)) {
      errors.push('Webhook type must be Slack or Discord.');
    }

    webhookUrl = normalizeUrl(body.webhookUrl);
    if (!webhookUrl || !isLikelyUrl(webhookUrl)) {
      errors.push('A valid webhook URL is required for ungrouped monitors.');
    }
  }

  const timeoutMs = clampNumber(
    body.timeoutMs,
    config.minTimeoutMs,
    config.maxTimeoutMs,
    existing ? existing.timeoutMs : config.defaultTimeoutMs
  );

  const monitorPayload = {
    name,
    groupId,
    groupName,
    checkType,
    host,
    url,
    keyword,
    keywordCaseSensitive: body.keywordCaseSensitive === 'on',
    httpStatusMode: body.httpStatusMode === '200' ? '200' : '2xx',
    tlsErrorAsFailure: body.tlsErrorAsFailure !== 'false',
    webhookType,
    webhookUrl,
    timeoutMs,
    active: body.active === 'on'
  };

  return {
    errors,
    monitorPayload
  };
}

function parseGroupForm(body) {
  const errors = [];
  const name = String(body.name || '').trim();
  const webhookType = safeLower(body.webhookType);
  const webhookUrl = normalizeUrl(body.webhookUrl);

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

function normalizeSlug(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

function parseStatusPageForm(body) {
  const errors = [];
  const name = String(body.name || '').trim();
  const slug = normalizeSlug(body.slug || body.name || '');

  const selectedMonitorIds = Array.isArray(body.monitorIds)
    ? body.monitorIds
    : body.monitorIds
      ? [body.monitorIds]
      : [];
  const monitorIds = selectedMonitorIds.map((id) => String(id || '').trim()).filter(Boolean);

  if (!name) {
    errors.push('Status page name is required.');
  }

  if (!slug) {
    errors.push('Status page slug is required.');
  } else if (!/^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$/.test(slug)) {
    errors.push('Status page slug must be 1-80 characters and use lowercase letters, numbers, or dashes.');
  }

  if (monitorIds.length === 0) {
    errors.push('Select at least one monitor.');
  }

  return {
    errors,
    payload: {
      name,
      slug,
      monitorIds
    }
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
  if (input.active !== undefined) {
    normalized.active = input.active ? 'on' : '';
  }

  return normalized;
}

function apiError(res, status, error, details = null) {
  res.status(status).json({
    error,
    ...(details ? { details } : {})
  });
}

function serializeMonitorForApi(monitor) {
  const uptime = store.calculateMonitorUptimeStats(monitor.id, undefined, monitor.userId || null);
  const uptimeRatio = uptime && Number.isFinite(uptime.uptimeRatio) ? Math.max(0, Math.min(1, uptime.uptimeRatio)) : null;
  const runtimeStatus = monitor.runtime && monitor.runtime.status ? monitor.runtime.status : 'unknown';
  const statusClass = monitor.active ? runtimeStatus : 'paused';
  const displayStatus = monitor.active
    ? runtimeStatus === 'up' && monitor.runtime && monitor.runtime.lastError
      ? 'up (confirming)'
      : runtimeStatus
    : 'paused';

  return {
    id: monitor.id,
    name: monitor.name,
    groupId: monitor.groupId || null,
    groupName: monitor.groupName || 'Ungrouped',
    sortOrder: monitor.sortOrder || 0,
    checkType: monitor.checkType,
    target: monitorTarget(monitor) || '',
    host: monitor.host,
    url: monitor.url,
    keyword: monitor.keyword,
    keywordCaseSensitive: monitor.keywordCaseSensitive,
    httpStatusMode: monitor.httpStatusMode,
    tlsErrorAsFailure: monitor.tlsErrorAsFailure,
    webhookType: monitor.webhookType,
    webhookUrl: monitor.webhookUrl,
    timeoutMs: monitor.timeoutMs,
    active: monitor.active,
    statusClass,
    displayStatus,
    runtime: monitor.runtime,
    uptimePercent: formatUptimePercent(uptimeRatio),
    uptimeRatio
  };
}

function formatUptimePercent(ratio) {
  if (!Number.isFinite(ratio)) {
    return 'N/A';
  }

  const percent = Math.max(0, Math.min(100, ratio * 100));
  return `${percent.toFixed(3)}%`;
}

function buildPublicStatusSnapshot(slug) {
  const statusPage = store.getStatusPageBySlug(slug);
  if (!statusPage) {
    return null;
  }

  const nowMs = Date.now();
  const openIncidentsByMonitorId = new Map(
    store.listOpenIncidents(statusPage.userId || null).map((incident) => [incident.monitorId, incident])
  );
  const recoveryTimesByMonitorId = store.getLatestRecoveryTimesByMonitorIds(statusPage.monitors.map((monitor) => monitor.id));
  const monitors = statusPage.monitors.map((monitor) => {
    const uptime = store.calculateMonitorUptimeStats(monitor.id, undefined, statusPage.userId || null);
    const uptimeRatio = uptime && Number.isFinite(uptime.uptimeRatio) ? Math.max(0, Math.min(1, uptime.uptimeRatio)) : null;
    const status = monitor.runtime.status || 'unknown';
    const openIncident = openIncidentsByMonitorId.get(monitor.id) || null;
    const lastRecoveryAt = recoveryTimesByMonitorId[monitor.id] || null;
    const stateSince =
      status === 'down'
        ? openIncident
          ? openIncident.startedAt
          : monitor.runtime.lastFailureAt || monitor.runtime.lastCheckAt || null
        : status === 'up'
          ? lastRecoveryAt || monitor.runtime.firstSuccessAt || monitor.createdAt || null
          : monitor.runtime.lastCheckAt || null;

    return {
      id: monitor.id,
      name: monitor.name,
      status,
      uptimePercent: formatUptimePercent(uptimeRatio),
      uptimeRatio,
      stateSince,
      stateDurationSeconds: stateSince ? elapsedSecondsSince(stateSince, nowMs) : null
    };
  });

  return {
    generatedAt: new Date().toISOString(),
    uptimeGoalPercent: 99.999,
    statusPage: {
      id: statusPage.id,
      slug: statusPage.slug,
      name: statusPage.name
    },
    monitors,
    summary: {
      total: monitors.length,
      up: monitors.filter((monitor) => monitor.status === 'up').length,
      down: monitors.filter((monitor) => monitor.status === 'down').length,
      unknown: monitors.filter((monitor) => monitor.status === 'unknown').length
    }
  };
}

app.use((req, res, next) => {
  res.locals.appName = config.appName;
  res.locals.flash = req.session.flash || null;
  res.locals.authenticated = Boolean(req.session.authenticatedUserId);

  if (req.session.flash) {
    delete req.session.flash;
  }

  next();
});

app.get('/healthz', (_req, res) => {
  res.status(200).json({
    ok: true,
    now: new Date().toISOString()
  });
});

app.get('/status/:slug', (req, res) => {
  const snapshot = buildPublicStatusSnapshot(req.params.slug);
  if (!snapshot) {
    res.status(404).render('public-status-page', {
      statusPage: null,
      monitors: [],
      uptimeGoalPercent: 99.999,
      generatedAt: new Date().toISOString(),
      summary: {
        total: 0,
        up: 0,
        down: 0,
        unknown: 0
      }
    });
    return;
  }

  res.render('public-status-page', {
    statusPage: snapshot.statusPage,
    monitors: snapshot.monitors,
    uptimeGoalPercent: snapshot.uptimeGoalPercent,
    generatedAt: snapshot.generatedAt,
    summary: snapshot.summary
  });
});

app.get('/api/status/:slug/live', (req, res) => {
  const snapshot = buildPublicStatusSnapshot(req.params.slug);
  if (!snapshot) {
    res.status(404).json({
      error: 'Status page not found'
    });
    return;
  }

  res.json(snapshot);
});

app.get(
  '/setup',
  asyncHandler(async (req, res) => {
    if (store.hasUsers()) {
      res.redirect('/login');
      return;
    }

    if (!req.session.setupTotpSecret || !req.session.setupTotpOtpauth) {
      const secret = speakeasy.generateSecret({
        name: `${config.appName} (${process.env.HOSTNAME || 'server'})`
      });

      req.session.setupTotpSecret = secret.base32;
      req.session.setupTotpOtpauth = secret.otpauth_url;
    }

    const qrCodeDataUrl = await QRCode.toDataURL(req.session.setupTotpOtpauth);

    res.render('setup', {
      qrCodeDataUrl
    });
  })
);

app.post(
  '/setup',
  asyncHandler(async (req, res) => {
    if (store.hasUsers()) {
      res.redirect('/login');
      return;
    }

    const username = String(req.body.username || '').trim();
    const submittedPassword = String(req.body.password || '');
    const otpCode = String(req.body.otpCode || '').replace(/\s+/g, '');

    if (!username || !submittedPassword || !otpCode) {
      setFlash(req, 'error', 'All setup fields are required.');
      res.redirect('/setup');
      return;
    }

    if (!req.session.setupTotpSecret) {
      setFlash(req, 'error', 'Setup session expired. Reload and try again.');
      res.redirect('/setup');
      return;
    }

    const otpValid = speakeasy.totp.verify({
      secret: req.session.setupTotpSecret,
      encoding: 'base32',
      token: otpCode,
      window: 1
    });

    if (!otpValid) {
      setFlash(req, 'error', 'Invalid TOTP code.');
      res.redirect('/setup');
      return;
    }

    const passwordHash = await bcrypt.hash(submittedPassword, 12);

    store.createUser({
      username,
      passwordHash,
      totpSecret: req.session.setupTotpSecret
    });

    clearSetupSecret(req);
    await regenerateSession(req);

    setFlash(req, 'success', 'Account created. Sign in to continue.');
    res.redirect('/login');
  })
);

app.get('/login', (req, res) => {
  if (!store.hasUsers()) {
    res.redirect('/setup');
    return;
  }

  if (req.session.authenticatedUserId) {
    res.redirect('/');
    return;
  }

  res.render('login');
});

app.post(
  '/login',
  asyncHandler(async (req, res) => {
    if (!store.hasUsers()) {
      res.redirect('/setup');
      return;
    }

    const username = String(req.body.username || '').trim();
    const submittedPassword = String(req.body.password || '');

    const user = store.findUserByUsername(username);
    if (!user) {
      setFlash(req, 'error', 'Invalid username or password.');
      res.redirect('/login');
      return;
    }

    const validPassword = await bcrypt.compare(submittedPassword, user.passwordHash);
    if (!validPassword) {
      setFlash(req, 'error', 'Invalid username or password.');
      res.redirect('/login');
      return;
    }

    await regenerateSession(req);
    req.session.pendingMfaUserId = user.id;
    await saveSession(req);
    res.redirect('/mfa');
  })
);

app.get('/mfa', (req, res) => {
  if (!req.session.pendingMfaUserId) {
    res.redirect('/login');
    return;
  }

  res.render('mfa');
});

app.post(
  '/mfa',
  asyncHandler(async (req, res) => {
    const pendingId = req.session.pendingMfaUserId;
    if (!pendingId) {
      res.redirect('/login');
      return;
    }

    const otpCode = String(req.body.otpCode || '').replace(/\s+/g, '');
    const user = store.findUserById(pendingId);

    if (!user) {
      req.session.pendingMfaUserId = null;
      setFlash(req, 'error', 'Login session expired. Please sign in again.');
      res.redirect('/login');
      return;
    }

    const validOtp = speakeasy.totp.verify({
      secret: user.totpSecret,
      encoding: 'base32',
      token: otpCode,
      window: 1
    });

    if (!validOtp) {
      setFlash(req, 'error', 'Invalid MFA code.');
      res.redirect('/mfa');
      return;
    }

    await regenerateSession(req);
    req.session.authenticatedUserId = user.id;
    await saveSession(req);
    res.redirect('/');
  })
);

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('argus_sid', {
      path: '/',
      httpOnly: true,
      sameSite: sessionCookieOptions.sameSite,
      secure: sessionCookieOptions.secure
    });
    res.clearCookie(sessionCookieName, {
      path: '/',
      httpOnly: true,
      sameSite: sessionCookieOptions.sameSite,
      secure: sessionCookieOptions.secure
    });
    res.redirect('/login');
  });
});

app.get(
  '/',
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = req.authenticatedUser.id;
    const snapshot = buildDashboardSnapshot({
      userId,
      eventsPage: req.query.eventsPage,
      includeEvents: true,
      includeIncidents: true
    });

    res.render('dashboard', {
      groupedMonitors: snapshot.groupedMonitors,
      incidents: snapshot.incidents,
      incidentsByMonitor: snapshot.incidentsByMonitor,
      events: snapshot.events,
      operationalEvents: snapshot.operationalEvents,
      summary: snapshot.summary,
      activeOutages: snapshot.activeOutages,
      generatedAt: snapshot.generatedAt,
      eventPagination: snapshot.eventPagination
    });
  })
);

app.get(
  '/api/dashboard/live',
  requireAuth,
  asyncHandler(async (req, res) => {
    const snapshot = buildDashboardSnapshot({
      userId: req.authenticatedUser.id,
      includeEvents: false,
      includeIncidents: false
    });

    res.json({
      generatedAt: snapshot.generatedAt,
      summary: snapshot.summary,
      groupedMonitors: snapshot.groupedMonitors,
      activeOutages: snapshot.activeOutages
    });
  })
);

app.get('/monitors/new', requireAuth, (req, res) => {
  const groups = store.listGroups(req.authenticatedUser.id);
  res.render('monitor-form', {
    editing: false,
    groups,
    monitor: {
      name: '',
      groupId: '',
      groupName: '',
      checkType: 'http',
      host: '',
      url: '',
      keyword: '',
      keywordCaseSensitive: false,
      httpStatusMode: '2xx',
      tlsErrorAsFailure: true,
      webhookType: 'slack',
      webhookUrl: '',
      timeoutMs: config.defaultTimeoutMs,
      active: true
    }
  });
});

app.post('/monitors', requireAuth, (req, res) => {
  const userId = req.authenticatedUser.id;
  const { errors, monitorPayload } = parseMonitorForm(req.body, null, userId);
  if (errors.length > 0) {
    setFlash(req, 'error', errors.join(' '));
    res.redirect('/monitors/new');
    return;
  }

  const created = store.createMonitor({
    ...monitorPayload,
    userId
  });

  store.addEvent({
    userId,
    monitorId: created.id,
    monitorName: created.name,
    eventType: 'monitor_created',
    message: `Monitor created (${created.checkType})`,
    details: {
      target: monitorTarget(created)
    }
  });

  engine.syncMonitors();

  setFlash(req, 'success', 'Monitor created.');
  res.redirect('/');
});

app.get('/monitors/:id/edit', requireAuth, (req, res) => {
  const userId = req.authenticatedUser.id;
  const groups = store.listGroups(userId);
  const monitor = store.getMonitorById(req.params.id, userId);
  if (!monitor) {
    setFlash(req, 'error', 'Monitor not found.');
    res.redirect('/');
    return;
  }

  res.render('monitor-form', {
    editing: true,
    groups,
    monitor
  });
});

app.post('/monitors/:id/update', requireAuth, (req, res) => {
  const userId = req.authenticatedUser.id;
  const existing = store.getMonitorById(req.params.id, userId);
  if (!existing) {
    setFlash(req, 'error', 'Monitor not found.');
    res.redirect('/');
    return;
  }

  const { errors, monitorPayload } = parseMonitorForm(req.body, existing, userId);
  if (errors.length > 0) {
    setFlash(req, 'error', errors.join(' '));
    res.redirect(`/monitors/${req.params.id}/edit`);
    return;
  }

  const updated = store.updateMonitor(req.params.id, monitorPayload, userId);
  if (!updated) {
    setFlash(req, 'error', 'Failed to update monitor.');
    res.redirect('/');
    return;
  }

  // If a monitor is edited while in a down incident, suppress "recovery" alerts caused by config edits.
  const openIncident = store.getOpenIncidentByMonitorId(updated.id);
  if (openIncident) {
    const endedAt = new Date().toISOString();
    store.closeIncident(openIncident.id, {
      endedAt,
      recoveryReason: 'Monitor updated (recovery alert suppressed)'
    });

    store.updateMonitorRuntime(updated.id, {
      status: 'unknown',
      lastError: null,
      nextCheckAt: null
    });

    store.addEvent({
      userId,
      monitorId: updated.id,
      monitorName: updated.name,
      eventType: 'monitor_edit_alert_suppressed',
      message: 'Suppressed recovery alert because monitor was edited during an active incident',
      details: {
        previousIncidentId: openIncident.id
      }
    });
  }

  store.addEvent({
    userId,
    monitorId: updated.id,
    monitorName: updated.name,
    eventType: 'monitor_updated',
    message: 'Monitor settings updated',
    details: {
      target: monitorTarget(updated)
    }
  });

  engine.syncMonitors();

  setFlash(req, 'success', 'Monitor updated.');
  res.redirect('/');
});

app.post('/monitors/:id/toggle', requireAuth, (req, res) => {
  const userId = req.authenticatedUser.id;
  const monitor = store.getMonitorById(req.params.id, userId);
  if (!monitor) {
    setFlash(req, 'error', 'Monitor not found.');
    res.redirect('/');
    return;
  }

  const updated = store.updateMonitor(
    monitor.id,
    {
      active: !monitor.active
    },
    userId
  );

  store.addEvent({
    userId,
    monitorId: updated.id,
    monitorName: updated.name,
    eventType: updated.active ? 'monitor_resumed' : 'monitor_paused',
    message: updated.active ? 'Monitor resumed' : 'Monitor paused',
    details: {
      target: monitorTarget(updated)
    }
  });

  engine.syncMonitors();

  setFlash(req, 'success', updated.active ? 'Monitor resumed.' : 'Monitor paused.');
  res.redirect('/');
});

app.post('/monitors/:id/delete', requireAuth, (req, res) => {
  const userId = req.authenticatedUser.id;
  const monitor = store.getMonitorById(req.params.id, userId);
  if (!monitor) {
    setFlash(req, 'error', 'Monitor not found.');
    res.redirect('/');
    return;
  }

  store.addEvent({
    userId,
    monitorId: monitor.id,
    monitorName: monitor.name,
    eventType: 'monitor_deleted',
    message: 'Monitor deleted',
    details: {
      target: monitorTarget(monitor)
    }
  });

  store.deleteMonitor(req.params.id, userId);
  engine.syncMonitors();

  setFlash(req, 'success', 'Monitor deleted.');
  res.redirect('/');
});

app.post('/monitors/:id/move', requireAuth, (req, res) => {
  const userId = req.authenticatedUser.id;
  const direction = req.body.direction === 'up' ? 'up' : 'down';
  const moved = store.moveMonitorInGroup(req.params.id, direction, userId);
  if (!moved) {
    setFlash(req, 'error', 'Monitor not found.');
    res.redirect('/');
    return;
  }

  store.addEvent({
    userId,
    monitorId: moved.id,
    monitorName: moved.name,
    eventType: 'monitor_reordered',
    message: `Monitor moved ${direction}`,
    details: {
      sortOrder: moved.sortOrder
    }
  });

  setFlash(req, 'success', `Monitor moved ${direction}.`);
  res.redirect('/');
});

app.post(
  '/monitors/:id/alert',
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = req.authenticatedUser.id;
    const monitor = store.getMonitorById(req.params.id, userId);
    if (!monitor) {
      setFlash(req, 'error', 'Monitor not found.');
      res.redirect('/');
      return;
    }

    const alertResult = await sendManualStatusAlert(monitor, 'manual monitor alert');

    store.addEvent({
      userId,
      monitorId: monitor.id,
      monitorName: monitor.name,
      eventType: alertResult.ok ? 'manual_alert_sent' : 'manual_alert_failed',
      message: alertResult.ok
        ? 'Manual status alert sent'
        : `Manual status alert failed: ${alertResult.error || 'unknown error'}`,
      details: {
        channel: monitor.webhookType,
        skipped: Boolean(alertResult.skipped)
      }
    });

    setFlash(
      req,
      alertResult.ok ? 'success' : 'error',
      alertResult.ok ? `Status alert sent for ${monitor.name}.` : `Failed to alert ${monitor.name}: ${alertResult.error}`
    );
    res.redirect('/');
  })
);

app.post(
  '/groups/:id/alert',
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = req.authenticatedUser.id;
    const groupId = req.params.id === 'ungrouped' ? null : req.params.id;
    if (groupId) {
      const group = store.getGroupById(groupId, userId);
      if (!group) {
        setFlash(req, 'error', 'Group not found.');
        res.redirect('/');
        return;
      }
    }

    const monitors = store
      .listMonitors(userId)
      .filter((monitor) => (groupId ? monitor.groupId === groupId : monitor.groupId === null));

    if (monitors.length === 0) {
      setFlash(req, 'error', 'No monitors in this group.');
      res.redirect('/');
      return;
    }

    let ok = 0;
    let failed = 0;

    for (const monitor of monitors) {
      const alertResult = await sendManualStatusAlert(monitor, 'manual group alert');
      if (alertResult.ok) {
        ok += 1;
      } else {
        failed += 1;
      }

      store.addEvent({
        userId,
        monitorId: monitor.id,
        monitorName: monitor.name,
        eventType: alertResult.ok ? 'manual_alert_sent' : 'manual_alert_failed',
        message: alertResult.ok
          ? 'Manual status alert sent'
          : `Manual status alert failed: ${alertResult.error || 'unknown error'}`,
        details: {
          channel: monitor.webhookType,
          skipped: Boolean(alertResult.skipped),
          groupAlert: true
        }
      });
    }

    setFlash(
      req,
      failed > 0 ? 'error' : 'success',
      failed > 0
        ? `Group alert finished: sent=${ok}, failed=${failed}.`
        : `Group alert sent for ${ok} monitor${ok === 1 ? '' : 's'}.`
    );
    res.redirect('/');
  })
);

app.get('/groups', requireAuth, (req, res) => {
  res.render('groups', {
    groups: store.listGroups(req.authenticatedUser.id)
  });
});

app.post('/groups', requireAuth, (req, res) => {
  const userId = req.authenticatedUser.id;
  const { errors, payload } = parseGroupForm(req.body);
  if (errors.length > 0) {
    setFlash(req, 'error', errors.join(' '));
    res.redirect('/groups');
    return;
  }

  try {
    const created = store.createGroup({
      ...payload,
      userId
    });
    store.addEvent({
      userId,
      eventType: 'group_created',
      message: `Group created: ${created.name}`,
      details: {
        groupId: created.id
      }
    });

    setFlash(req, 'success', 'Group created.');
    res.redirect('/groups');
  } catch (error) {
    setFlash(req, 'error', error.message || 'Failed to create group.');
    res.redirect('/groups');
  }
});

app.post('/groups/:id/update', requireAuth, (req, res) => {
  const userId = req.authenticatedUser.id;
  const existing = store.getGroupById(req.params.id, userId);
  if (!existing) {
    setFlash(req, 'error', 'Group not found.');
    res.redirect('/groups');
    return;
  }

  const { errors, payload } = parseGroupForm(req.body);
  if (errors.length > 0) {
    setFlash(req, 'error', errors.join(' '));
    res.redirect('/groups');
    return;
  }

  try {
    const updated = store.updateGroup(req.params.id, payload, userId);
    store.addEvent({
      userId,
      eventType: 'group_updated',
      message: `Group updated: ${updated.name}`,
      details: {
        groupId: updated.id
      }
    });

    setFlash(req, 'success', 'Group updated.');
    res.redirect('/groups');
  } catch (error) {
    setFlash(req, 'error', error.message || 'Failed to update group.');
    res.redirect('/groups');
  }
});

app.post('/groups/:id/delete', requireAuth, (req, res) => {
  const userId = req.authenticatedUser.id;
  const removed = store.deleteGroup(req.params.id, userId);
  if (!removed) {
    setFlash(req, 'error', 'Group not found.');
    res.redirect('/groups');
    return;
  }

  store.addEvent({
    userId,
    eventType: 'group_deleted',
    message: `Group deleted: ${removed.name}`,
    details: {
      groupId: removed.id
    }
  });

  setFlash(req, 'success', 'Group deleted. Monitors were moved to ungrouped with inherited webhook settings.');
  res.redirect('/groups');
});

app.get('/status-pages', requireAuth, (req, res) => {
  const userId = req.authenticatedUser.id;
  const monitors = store.listMonitors(userId);
  const monitorGroupMap = new Map();

  for (const monitor of monitors) {
    const groupId = monitor.groupId || null;
    const key = groupId || 'ungrouped';
    const groupName = groupId ? monitor.groupName || 'Ungrouped' : 'Ungrouped';

    if (!monitorGroupMap.has(key)) {
      monitorGroupMap.set(key, {
        id: groupId,
        name: groupName,
        monitors: []
      });
    }

    monitorGroupMap.get(key).monitors.push(monitor);
  }

  const groupedMonitors = Array.from(monitorGroupMap.values())
    .sort((left, right) => {
      if (!left.id && right.id) {
        return 1;
      }
      if (left.id && !right.id) {
        return -1;
      }
      return left.name.localeCompare(right.name);
    })
    .map((group) => ({
      ...group,
      monitors: group.monitors
        .slice()
        .sort(
          (left, right) =>
            (left.sortOrder || 0) - (right.sortOrder || 0) || left.name.localeCompare(right.name)
        )
    }));

  res.render('status-pages', {
    statusPages: store.listStatusPages(userId),
    monitors,
    groupedMonitors
  });
});

app.post('/status-pages', requireAuth, (req, res) => {
  const userId = req.authenticatedUser.id;
  const { errors, payload } = parseStatusPageForm(req.body);
  if (errors.length > 0) {
    setFlash(req, 'error', errors.join(' '));
    res.redirect('/status-pages');
    return;
  }

  try {
    const created = store.createStatusPage({
      ...payload,
      userId
    });

    store.addEvent({
      userId,
      eventType: 'status_page_created',
      message: `Status page created: ${created.name}`,
      details: {
        statusPageId: created.id,
        slug: created.slug,
        monitorCount: created.monitorCount
      }
    });

    setFlash(req, 'success', `Status page created: /status/${created.slug}`);
    res.redirect('/status-pages');
  } catch (error) {
    setFlash(req, 'error', error.message || 'Failed to create status page.');
    res.redirect('/status-pages');
  }
});

app.post('/status-pages/:id/delete', requireAuth, (req, res) => {
  const userId = req.authenticatedUser.id;
  const removed = store.deleteStatusPage(req.params.id, userId);
  if (!removed) {
    setFlash(req, 'error', 'Status page not found.');
    res.redirect('/status-pages');
    return;
  }

  store.addEvent({
    userId,
    eventType: 'status_page_deleted',
    message: `Status page deleted: ${removed.name}`,
    details: {
      statusPageId: removed.id,
      slug: removed.slug
    }
  });

  setFlash(req, 'success', 'Status page deleted.');
  res.redirect('/status-pages');
});

const apiRouter = express.Router();
apiRouter.use(requireApiKey);

apiRouter.get('/me', (req, res) => {
  res.json({
    id: req.apiUser.id,
    username: req.apiUser.username
  });
});

apiRouter.get('/dashboard', (req, res) => {
  const snapshot = buildDashboardSnapshot({
    userId: req.apiUser.id,
    includeEvents: true,
    includeIncidents: true
  });
  res.json(snapshot);
});

apiRouter.get('/events', (req, res) => {
  const limit = clampNumber(req.query.limit, 1, 500, 100);
  const offset = clampNumber(req.query.offset, 0, 100000, 0);
  res.json({
    limit,
    offset,
    events: store.listEvents(limit, offset, req.apiUser.id)
  });
});

apiRouter.get('/incidents', (req, res) => {
  const limit = clampNumber(req.query.limit, 1, 500, 100);
  res.json({
    limit,
    incidents: store.listIncidents(limit, req.apiUser.id)
  });
});

apiRouter.get('/groups', (req, res) => {
  res.json({
    groups: store.listGroups(req.apiUser.id)
  });
});

apiRouter.post('/groups', (req, res) => {
  const { errors, payload } = parseGroupForm(req.body || {});
  if (errors.length > 0) {
    apiError(res, 400, 'Validation failed.', errors);
    return;
  }

  try {
    const created = store.createGroup({
      ...payload,
      userId: req.apiUser.id
    });
    store.addEvent({
      userId: req.apiUser.id,
      eventType: 'group_created',
      message: `Group created: ${created.name}`,
      details: {
        groupId: created.id,
        source: 'api'
      }
    });
    res.status(201).json({
      group: created
    });
  } catch (error) {
    apiError(res, 400, error.message || 'Failed to create group.');
  }
});

apiRouter.get('/groups/:id', (req, res) => {
  const group = store.getGroupById(req.params.id, req.apiUser.id);
  if (!group) {
    apiError(res, 404, 'Group not found.');
    return;
  }
  res.json({
    group
  });
});

apiRouter.patch('/groups/:id', (req, res) => {
  const existing = store.getGroupById(req.params.id, req.apiUser.id);
  if (!existing) {
    apiError(res, 404, 'Group not found.');
    return;
  }

  const merged = {
    name: req.body && req.body.name !== undefined ? req.body.name : existing.name,
    webhookType: req.body && req.body.webhookType !== undefined ? req.body.webhookType : existing.webhookType,
    webhookUrl: req.body && req.body.webhookUrl !== undefined ? req.body.webhookUrl : existing.webhookUrl
  };
  const { errors, payload } = parseGroupForm(merged);
  if (errors.length > 0) {
    apiError(res, 400, 'Validation failed.', errors);
    return;
  }

  try {
    const updated = store.updateGroup(req.params.id, payload, req.apiUser.id);
    store.addEvent({
      userId: req.apiUser.id,
      eventType: 'group_updated',
      message: `Group updated: ${updated.name}`,
      details: {
        groupId: updated.id,
        source: 'api'
      }
    });
    res.json({
      group: updated
    });
  } catch (error) {
    apiError(res, 400, error.message || 'Failed to update group.');
  }
});

apiRouter.delete('/groups/:id', (req, res) => {
  const removed = store.deleteGroup(req.params.id, req.apiUser.id);
  if (!removed) {
    apiError(res, 404, 'Group not found.');
    return;
  }

  store.addEvent({
    userId: req.apiUser.id,
    eventType: 'group_deleted',
    message: `Group deleted: ${removed.name}`,
    details: {
      groupId: removed.id,
      source: 'api'
    }
  });

  res.json({
    deleted: true
  });
});

apiRouter.post(
  '/groups/:id/alert',
  asyncHandler(async (req, res) => {
    const groupId = req.params.id === 'ungrouped' ? null : req.params.id;
    if (groupId) {
      const group = store.getGroupById(groupId, req.apiUser.id);
      if (!group) {
        apiError(res, 404, 'Group not found.');
        return;
      }
    }

    const monitors = store
      .listMonitors(req.apiUser.id)
      .filter((monitor) => (groupId ? monitor.groupId === groupId : monitor.groupId === null));
    if (monitors.length === 0) {
      apiError(res, 400, 'No monitors found for this group.');
      return;
    }

    let sent = 0;
    let failed = 0;
    for (const monitor of monitors) {
      const alertResult = await sendManualStatusAlert(monitor, 'api group alert');
      if (alertResult.ok) {
        sent += 1;
      } else {
        failed += 1;
      }

      store.addEvent({
        userId: req.apiUser.id,
        monitorId: monitor.id,
        monitorName: monitor.name,
        eventType: alertResult.ok ? 'manual_alert_sent' : 'manual_alert_failed',
        message: alertResult.ok
          ? 'Manual status alert sent'
          : `Manual status alert failed: ${alertResult.error || 'unknown error'}`,
        details: {
          channel: monitor.webhookType,
          skipped: Boolean(alertResult.skipped),
          groupAlert: true,
          source: 'api'
        }
      });
    }

    res.json({
      sent,
      failed
    });
  })
);

apiRouter.get('/monitors', (req, res) => {
  const monitors = store.listMonitors(req.apiUser.id).map((monitor) => serializeMonitorForApi(monitor));
  res.json({
    monitors
  });
});

apiRouter.post('/monitors', (req, res) => {
  const normalizedBody = normalizeApiMonitorBody(req.body || null, null);
  const { errors, monitorPayload } = parseMonitorForm(normalizedBody, null, req.apiUser.id);
  if (errors.length > 0) {
    apiError(res, 400, 'Validation failed.', errors);
    return;
  }

  const created = store.createMonitor({
    ...monitorPayload,
    userId: req.apiUser.id
  });
  store.addEvent({
    userId: req.apiUser.id,
    monitorId: created.id,
    monitorName: created.name,
    eventType: 'monitor_created',
    message: `Monitor created (${created.checkType})`,
    details: {
      target: monitorTarget(created),
      source: 'api'
    }
  });

  engine.syncMonitors();
  res.status(201).json({
    monitor: serializeMonitorForApi(created)
  });
});

apiRouter.get('/monitors/:id', (req, res) => {
  const monitor = store.getMonitorById(req.params.id, req.apiUser.id);
  if (!monitor) {
    apiError(res, 404, 'Monitor not found.');
    return;
  }

  res.json({
    monitor: serializeMonitorForApi(monitor)
  });
});

apiRouter.patch('/monitors/:id', (req, res) => {
  const existing = store.getMonitorById(req.params.id, req.apiUser.id);
  if (!existing) {
    apiError(res, 404, 'Monitor not found.');
    return;
  }

  const normalizedBody = normalizeApiMonitorBody(req.body || null, existing);
  const { errors, monitorPayload } = parseMonitorForm(normalizedBody, existing, req.apiUser.id);
  if (errors.length > 0) {
    apiError(res, 400, 'Validation failed.', errors);
    return;
  }

  const updated = store.updateMonitor(req.params.id, monitorPayload, req.apiUser.id);
  if (!updated) {
    apiError(res, 500, 'Failed to update monitor.');
    return;
  }

  store.addEvent({
    userId: req.apiUser.id,
    monitorId: updated.id,
    monitorName: updated.name,
    eventType: 'monitor_updated',
    message: 'Monitor settings updated',
    details: {
      target: monitorTarget(updated),
      source: 'api'
    }
  });

  engine.syncMonitors();
  res.json({
    monitor: serializeMonitorForApi(updated)
  });
});

apiRouter.post('/monitors/:id/pause', (req, res) => {
  const monitor = store.getMonitorById(req.params.id, req.apiUser.id);
  if (!monitor) {
    apiError(res, 404, 'Monitor not found.');
    return;
  }

  if (!monitor.active) {
    res.json({
      monitor: serializeMonitorForApi(monitor)
    });
    return;
  }

  const updated = store.updateMonitor(monitor.id, { active: false }, req.apiUser.id);
  store.addEvent({
    userId: req.apiUser.id,
    monitorId: updated.id,
    monitorName: updated.name,
    eventType: 'monitor_paused',
    message: 'Monitor paused',
    details: {
      target: monitorTarget(updated),
      source: 'api'
    }
  });
  engine.syncMonitors();
  res.json({
    monitor: serializeMonitorForApi(updated)
  });
});

apiRouter.post('/monitors/:id/resume', (req, res) => {
  const monitor = store.getMonitorById(req.params.id, req.apiUser.id);
  if (!monitor) {
    apiError(res, 404, 'Monitor not found.');
    return;
  }

  if (monitor.active) {
    res.json({
      monitor: serializeMonitorForApi(monitor)
    });
    return;
  }

  const updated = store.updateMonitor(monitor.id, { active: true }, req.apiUser.id);
  store.addEvent({
    userId: req.apiUser.id,
    monitorId: updated.id,
    monitorName: updated.name,
    eventType: 'monitor_resumed',
    message: 'Monitor resumed',
    details: {
      target: monitorTarget(updated),
      source: 'api'
    }
  });
  engine.syncMonitors();
  res.json({
    monitor: serializeMonitorForApi(updated)
  });
});

apiRouter.post('/monitors/:id/move', (req, res) => {
  const direction = req.body && req.body.direction === 'up' ? 'up' : req.body && req.body.direction === 'down' ? 'down' : null;
  if (!direction) {
    apiError(res, 400, 'direction must be "up" or "down".');
    return;
  }

  const moved = store.moveMonitorInGroup(req.params.id, direction, req.apiUser.id);
  if (!moved) {
    apiError(res, 404, 'Monitor not found.');
    return;
  }

  store.addEvent({
    userId: req.apiUser.id,
    monitorId: moved.id,
    monitorName: moved.name,
    eventType: 'monitor_reordered',
    message: `Monitor moved ${direction}`,
    details: {
      sortOrder: moved.sortOrder,
      source: 'api'
    }
  });

  res.json({
    monitor: serializeMonitorForApi(moved)
  });
});

apiRouter.post(
  '/monitors/:id/alert',
  asyncHandler(async (req, res) => {
    const monitor = store.getMonitorById(req.params.id, req.apiUser.id);
    if (!monitor) {
      apiError(res, 404, 'Monitor not found.');
      return;
    }

    const alertResult = await sendManualStatusAlert(monitor, 'api monitor alert');
    store.addEvent({
      userId: req.apiUser.id,
      monitorId: monitor.id,
      monitorName: monitor.name,
      eventType: alertResult.ok ? 'manual_alert_sent' : 'manual_alert_failed',
      message: alertResult.ok
        ? 'Manual status alert sent'
        : `Manual status alert failed: ${alertResult.error || 'unknown error'}`,
      details: {
        channel: monitor.webhookType,
        skipped: Boolean(alertResult.skipped),
        source: 'api'
      }
    });

    res.json({
      ok: Boolean(alertResult.ok),
      error: alertResult.ok ? null : alertResult.error || 'unknown error'
    });
  })
);

apiRouter.delete('/monitors/:id', (req, res) => {
  const monitor = store.getMonitorById(req.params.id, req.apiUser.id);
  if (!monitor) {
    apiError(res, 404, 'Monitor not found.');
    return;
  }

  store.addEvent({
    userId: req.apiUser.id,
    monitorId: monitor.id,
    monitorName: monitor.name,
    eventType: 'monitor_deleted',
    message: 'Monitor deleted',
    details: {
      target: monitorTarget(monitor),
      source: 'api'
    }
  });

  store.deleteMonitor(req.params.id, req.apiUser.id);
  engine.syncMonitors();

  res.json({
    deleted: true
  });
});

apiRouter.get('/status-pages', (req, res) => {
  res.json({
    statusPages: store.listStatusPages(req.apiUser.id)
  });
});

apiRouter.post('/status-pages', (req, res) => {
  const { errors, payload } = parseStatusPageForm(req.body || {});
  if (errors.length > 0) {
    apiError(res, 400, 'Validation failed.', errors);
    return;
  }

  try {
    const created = store.createStatusPage({
      ...payload,
      userId: req.apiUser.id
    });
    store.addEvent({
      userId: req.apiUser.id,
      eventType: 'status_page_created',
      message: `Status page created: ${created.name}`,
      details: {
        statusPageId: created.id,
        slug: created.slug,
        monitorCount: created.monitorCount,
        source: 'api'
      }
    });
    res.status(201).json({
      statusPage: created
    });
  } catch (error) {
    apiError(res, 400, error.message || 'Failed to create status page.');
  }
});

apiRouter.get('/status-pages/:id', (req, res) => {
  const statusPage = store.getStatusPageById(req.params.id, req.apiUser.id);
  if (!statusPage) {
    apiError(res, 404, 'Status page not found.');
    return;
  }
  res.json({
    statusPage
  });
});

apiRouter.delete('/status-pages/:id', (req, res) => {
  const removed = store.deleteStatusPage(req.params.id, req.apiUser.id);
  if (!removed) {
    apiError(res, 404, 'Status page not found.');
    return;
  }
  store.addEvent({
    userId: req.apiUser.id,
    eventType: 'status_page_deleted',
    message: `Status page deleted: ${removed.name}`,
    details: {
      statusPageId: removed.id,
      slug: removed.slug,
      source: 'api'
    }
  });
  res.json({
    deleted: true
  });
});

app.use('/api/v1', apiRouter);

function buildOpenApiSpec(req) {
  const origin = `${req.protocol}://${req.get('host')}`;
  return {
    openapi: '3.0.3',
    info: {
      title: 'Argus API',
      version: '1.0.0',
      description:
        'Programmatic API for Argus monitor, group, incident, and status page management. Use API keys via Bearer auth.'
    },
    servers: [
      {
        url: `${origin}/api/v1`
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer'
        }
      }
    },
    security: [
      {
        bearerAuth: []
      }
    ],
    paths: {
      '/me': {
        get: {
          summary: 'Get current API key owner'
        }
      },
      '/dashboard': {
        get: {
          summary: 'Get dashboard snapshot'
        }
      },
      '/events': {
        get: {
          summary: 'List events'
        }
      },
      '/incidents': {
        get: {
          summary: 'List incidents'
        }
      },
      '/groups': {
        get: {
          summary: 'List groups'
        },
        post: {
          summary: 'Create group'
        }
      },
      '/groups/{id}': {
        get: {
          summary: 'Get group'
        },
        patch: {
          summary: 'Update group'
        },
        delete: {
          summary: 'Delete group'
        }
      },
      '/groups/{id}/alert': {
        post: {
          summary: 'Send manual alerts for all monitors in a group'
        }
      },
      '/monitors': {
        get: {
          summary: 'List monitors'
        },
        post: {
          summary: 'Create monitor'
        }
      },
      '/monitors/{id}': {
        get: {
          summary: 'Get monitor'
        },
        patch: {
          summary: 'Update monitor'
        },
        delete: {
          summary: 'Delete monitor'
        }
      },
      '/monitors/{id}/pause': {
        post: {
          summary: 'Pause monitor'
        }
      },
      '/monitors/{id}/resume': {
        post: {
          summary: 'Resume monitor'
        }
      },
      '/monitors/{id}/move': {
        post: {
          summary: 'Reorder monitor inside group'
        }
      },
      '/monitors/{id}/alert': {
        post: {
          summary: 'Send manual monitor alert'
        }
      },
      '/status-pages': {
        get: {
          summary: 'List status pages'
        },
        post: {
          summary: 'Create status page'
        }
      },
      '/status-pages/{id}': {
        get: {
          summary: 'Get status page'
        },
        delete: {
          summary: 'Delete status page'
        }
      }
    }
  };
}

app.get('/api/openapi.json', (req, res) => {
  res.json(buildOpenApiSpec(req));
});

app.get('/api/docs', (req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Argus API Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
    <style>html,body,#swagger-ui{height:100%;margin:0}</style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.ui = SwaggerUIBundle({
        url: '/api/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true
      });
    </script>
  </body>
</html>`);
});

app.use((error, _req, res, _next) => {
  console.error(error);

  res.status(500).render('error', {
    errorMessage: 'An unexpected error occurred.'
  });
});

const server = app.listen(config.port, () => {
  console.log(`${config.appName} listening on port ${config.port}`);
});

function gracefulShutdown(signal) {
  console.log(`Received ${signal}, shutting down`);

  engine.stop();

  server.close(() => {
    store.close();
    process.exit(0);
  });
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
