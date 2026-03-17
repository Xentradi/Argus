const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const path = require('path');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const config = require('./config');
const { DataStore } = require('./store');
const { MonitorEngine } = require('./monitorEngine');
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

app.use(
  session({
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

function parseMonitorForm(body, existing = null) {
  const errors = [];

  const checkType = safeLower(body.checkType);
  const name = String(body.name || '').trim();
  const groupName = String(body.groupName || '').trim() || 'Default';
  const host = String(body.host || '').trim();
  const url = normalizeUrl(body.url);
  const keyword = String(body.keyword || '').trim();

  if (!name) {
    errors.push('Name is required.');
  }

  if (groupName.length > 120) {
    errors.push('Group name must be 120 characters or less.');
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

  const webhookType = safeLower(body.webhookType);
  if (!['slack', 'discord'].includes(webhookType)) {
    errors.push('Webhook type must be Slack or Discord.');
  }

  const webhookUrl = normalizeUrl(body.webhookUrl);
  if (!webhookUrl || !isLikelyUrl(webhookUrl)) {
    errors.push('A valid webhook URL is required.');
  }

  const timeoutMs = clampNumber(
    body.timeoutMs,
    config.minTimeoutMs,
    config.maxTimeoutMs,
    existing ? existing.timeoutMs : config.defaultTimeoutMs
  );

  const monitorPayload = {
    name,
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
  asyncHandler(async (_req, res) => {
    const monitors = store.listMonitors();
    const incidents = store.listIncidents(250);
    const events = store.listEvents(250);
    const groupedMap = new Map();

    for (const monitor of monitors) {
      const groupName = monitor.groupName || 'Default';
      if (!groupedMap.has(groupName)) {
        groupedMap.set(groupName, []);
      }
      groupedMap.get(groupName).push(monitor);
    }

    const groupedMonitors = Array.from(groupedMap.entries())
      .sort((left, right) => left[0].localeCompare(right[0]))
      .map(([groupName, groupMonitors]) => ({
        groupName,
        monitors: groupMonitors.slice().sort((left, right) => left.name.localeCompare(right.name))
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
      monitorTarget
    });
  })
);

app.get('/monitors/new', requireAuth, (req, res) => {
  res.render('monitor-form', {
    editing: false,
    monitor: {
      name: '',
      groupName: 'Default',
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
  const monitor = store.getMonitorById(req.params.id);
  if (!monitor) {
    setFlash(req, 'error', 'Monitor not found.');
    res.redirect('/');
    return;
  }

  res.render('monitor-form', {
    editing: true,
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
