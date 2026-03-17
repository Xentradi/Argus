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
  res.sendFile(path.join(__dirname, '..', 'public', 'img', 'argus.jpg'));
});

const sessionDbDir = path.dirname(config.dbFile);
const sessionDbFile = process.env.SESSION_DB_FILE || 'argus-sessions.sqlite';

app.use(
  session({
    store: new SQLiteStore({
      dir: sessionDbDir,
      db: sessionDbFile,
      table: 'sessions'
    }),
    name: 'argus_sid',
    secret: process.env.SESSION_SECRET || store.getSessionSecret(),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000
    }
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
    const password = String(req.body.password || '');
    const otpCode = String(req.body.otpCode || '').replace(/\s+/g, '');

    if (!username || !password || !otpCode) {
      setFlash(req, 'error', 'Username, password, and TOTP code are required.');
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

    const passwordHash = await bcrypt.hash(password, 12);

    store.createUser({
      username,
      passwordHash,
      totpSecret: req.session.setupTotpSecret
    });

    clearSetupSecret(req);

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
    const password = String(req.body.password || '');

    const user = store.findUserByUsername(username);
    if (!user) {
      setFlash(req, 'error', 'Invalid username or password.');
      res.redirect('/login');
      return;
    }

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) {
      setFlash(req, 'error', 'Invalid username or password.');
      res.redirect('/login');
      return;
    }

    req.session.pendingMfaUserId = user.id;
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

app.post('/mfa', (req, res) => {
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

  req.session.pendingMfaUserId = null;
  req.session.authenticatedUserId = user.id;
  req.session.save(() => {
    res.redirect('/');
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get(
  '/',
  requireAuth,
  asyncHandler(async (req, res) => {
    const monitors = store.listMonitors();
    const groups = store.listGroups();
    const incidents = store.listIncidents(250);
    const requestedEventsPage = clampNumber(req.query.eventsPage, 1, 1000000, 1);
    const eventsPerPage = 20;
    const totalEvents = store.countEvents();
    const totalEventPages = Math.max(1, Math.ceil(totalEvents / eventsPerPage));
    const eventsPage = Math.min(requestedEventsPage, totalEventPages);
    const eventsOffset = (eventsPage - 1) * eventsPerPage;
    const events = store.listEvents(eventsPerPage, eventsOffset);
    const groupsById = new Map(groups.map((group) => [group.id, group]));
    const groupedMap = new Map();

    for (const monitor of monitors) {
      const effectiveGroup = monitor.groupId ? groupsById.get(monitor.groupId) : null;
      const bucketKey = effectiveGroup ? effectiveGroup.id : 'ungrouped';
      const bucketName = effectiveGroup ? effectiveGroup.name : 'Ungrouped';

      if (!groupedMap.has(bucketKey)) {
        groupedMap.set(bucketKey, {
          groupId: effectiveGroup ? effectiveGroup.id : null,
          groupName: bucketName,
          monitors: []
        });
      }
      groupedMap.get(bucketKey).monitors.push(monitor);
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
      total: monitors.length,
      groups: groupedMonitors.length,
      up: monitors.filter((monitor) => monitor.runtime.status === 'up').length,
      down: monitors.filter((monitor) => monitor.runtime.status === 'down').length,
      unknown: monitors.filter((monitor) => monitor.runtime.status === 'unknown').length
    };

    res.render('dashboard', {
      groupedMonitors,
      incidents,
      events,
      summary,
      monitorTarget,
      eventPagination: {
        page: eventsPage,
        totalPages: totalEventPages,
        hasPrev: eventsPage > 1,
        hasNext: eventsPage < totalEventPages
      }
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
