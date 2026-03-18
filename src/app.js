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

function buildDashboardSnapshot({ eventsPage = 1, includeEvents = true, includeIncidents = true } = {}) {
  const monitors = store.listMonitors();
  const groups = store.listGroups();
  const groupsById = new Map(groups.map((group) => [group.id, group]));
  const openIncidentsByMonitorId = new Map(store.listOpenIncidents().map((incident) => [incident.monitorId, incident]));
  const nowMs = Date.now();
  const groupedMap = new Map();
  const serializedMonitors = [];

  for (const monitor of monitors) {
    const effectiveGroup = monitor.groupId ? groupsById.get(monitor.groupId) : null;
    const bucketKey = effectiveGroup ? effectiveGroup.id : 'ungrouped';
    const bucketName = effectiveGroup ? effectiveGroup.name : 'Ungrouped';
    const status = monitor.runtime.status || 'unknown';
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
      hasUnconfirmedFailures: status === 'up' && Boolean(monitor.runtime.lastError),
      outage: {
        active: status === 'down',
        startedAt: downSince,
        durationSeconds: status === 'down' ? outageSeconds : null
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
    up: serializedMonitors.filter((monitor) => monitor.runtime.status === 'up').length,
    down: serializedMonitors.filter((monitor) => monitor.runtime.status === 'down').length,
    unknown: serializedMonitors.filter((monitor) => monitor.runtime.status === 'unknown').length
  };

  const activeOutages = serializedMonitors
    .filter((monitor) => monitor.runtime.status === 'down')
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
    const incidents = store.listIncidents(250).map((incident) => {
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
    const totalEvents = store.countEvents();
    const totalEventPages = Math.max(1, Math.ceil(totalEvents / eventsPerPage));
    const safeEventsPage = Math.min(requestedEventsPage, totalEventPages);
    const eventsOffset = (safeEventsPage - 1) * eventsPerPage;

    snapshot.events = store.listEvents(eventsPerPage, eventsOffset);
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

function parseMonitorForm(body, existing = null) {
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
    selectedGroup = store.getGroupById(groupId);
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
  const openIncidentsByMonitorId = new Map(store.listOpenIncidents().map((incident) => [incident.monitorId, incident]));
  const monitors = statusPage.monitors.map((monitor) => {
    const uptime = store.calculateMonitorUptimeStats(monitor.id);
    const status = monitor.runtime.status || 'unknown';
    const openIncident = openIncidentsByMonitorId.get(monitor.id) || null;
    const stateSince =
      status === 'down'
        ? openIncident
          ? openIncident.startedAt
          : monitor.runtime.lastFailureAt || monitor.runtime.lastCheckAt || null
        : status === 'up'
          ? monitor.runtime.lastSuccessAt || monitor.runtime.lastCheckAt || null
          : monitor.runtime.lastCheckAt || null;

    return {
      id: monitor.id,
      name: monitor.name,
      status,
      uptimePercent: formatUptimePercent(uptime ? uptime.uptimeRatio : Number.NaN),
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
    const snapshot = buildDashboardSnapshot({
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
  asyncHandler(async (_req, res) => {
    const snapshot = buildDashboardSnapshot({
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
  const groups = store.listGroups();
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
  const { errors, monitorPayload } = parseMonitorForm(req.body);
  if (errors.length > 0) {
    setFlash(req, 'error', errors.join(' '));
    res.redirect('/monitors/new');
    return;
  }

  const created = store.createMonitor(monitorPayload);

  store.addEvent({
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
  const groups = store.listGroups();
  const monitor = store.getMonitorById(req.params.id);
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
  const existing = store.getMonitorById(req.params.id);
  if (!existing) {
    setFlash(req, 'error', 'Monitor not found.');
    res.redirect('/');
    return;
  }

  const { errors, monitorPayload } = parseMonitorForm(req.body, existing);
  if (errors.length > 0) {
    setFlash(req, 'error', errors.join(' '));
    res.redirect(`/monitors/${req.params.id}/edit`);
    return;
  }

  const updated = store.updateMonitor(req.params.id, monitorPayload);
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
  const monitor = store.getMonitorById(req.params.id);
  if (!monitor) {
    setFlash(req, 'error', 'Monitor not found.');
    res.redirect('/');
    return;
  }

  const updated = store.updateMonitor(monitor.id, {
    active: !monitor.active
  });

  store.addEvent({
    monitorId: updated.id,
    monitorName: updated.name,
    eventType: updated.active ? 'monitor_enabled' : 'monitor_disabled',
    message: updated.active ? 'Monitor enabled' : 'Monitor disabled',
    details: {
      target: monitorTarget(updated)
    }
  });

  engine.syncMonitors();

  setFlash(req, 'success', updated.active ? 'Monitor enabled.' : 'Monitor disabled.');
  res.redirect('/');
});

app.post('/monitors/:id/delete', requireAuth, (req, res) => {
  const monitor = store.getMonitorById(req.params.id);
  if (!monitor) {
    setFlash(req, 'error', 'Monitor not found.');
    res.redirect('/');
    return;
  }

  store.addEvent({
    monitorId: monitor.id,
    monitorName: monitor.name,
    eventType: 'monitor_deleted',
    message: 'Monitor deleted',
    details: {
      target: monitorTarget(monitor)
    }
  });

  store.deleteMonitor(req.params.id);
  engine.syncMonitors();

  setFlash(req, 'success', 'Monitor deleted.');
  res.redirect('/');
});

app.post('/monitors/:id/move', requireAuth, (req, res) => {
  const direction = req.body.direction === 'up' ? 'up' : 'down';
  const moved = store.moveMonitorInGroup(req.params.id, direction);
  if (!moved) {
    setFlash(req, 'error', 'Monitor not found.');
    res.redirect('/');
    return;
  }

  store.addEvent({
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
    const monitor = store.getMonitorById(req.params.id);
    if (!monitor) {
      setFlash(req, 'error', 'Monitor not found.');
      res.redirect('/');
      return;
    }

    const alertResult = await sendManualStatusAlert(monitor, 'manual monitor alert');

    store.addEvent({
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
    const groupId = req.params.id === 'ungrouped' ? null : req.params.id;
    if (groupId) {
      const group = store.getGroupById(groupId);
      if (!group) {
        setFlash(req, 'error', 'Group not found.');
        res.redirect('/');
        return;
      }
    }

    const monitors = store
      .listMonitors()
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
    groups: store.listGroups()
  });
});

app.post('/groups', requireAuth, (req, res) => {
  const { errors, payload } = parseGroupForm(req.body);
  if (errors.length > 0) {
    setFlash(req, 'error', errors.join(' '));
    res.redirect('/groups');
    return;
  }

  try {
    const created = store.createGroup(payload);
    store.addEvent({
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
  const existing = store.getGroupById(req.params.id);
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
    const updated = store.updateGroup(req.params.id, payload);
    store.addEvent({
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
  const removed = store.deleteGroup(req.params.id);
  if (!removed) {
    setFlash(req, 'error', 'Group not found.');
    res.redirect('/groups');
    return;
  }

  store.addEvent({
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
  const monitors = store.listMonitors();
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
    statusPages: store.listStatusPages(),
    monitors,
    groupedMonitors
  });
});

app.post('/status-pages', requireAuth, (req, res) => {
  const { errors, payload } = parseStatusPageForm(req.body);
  if (errors.length > 0) {
    setFlash(req, 'error', errors.join(' '));
    res.redirect('/status-pages');
    return;
  }

  try {
    const created = store.createStatusPage(payload);

    store.addEvent({
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
  const removed = store.deleteStatusPage(req.params.id);
  if (!removed) {
    setFlash(req, 'error', 'Status page not found.');
    res.redirect('/status-pages');
    return;
  }

  store.addEvent({
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
