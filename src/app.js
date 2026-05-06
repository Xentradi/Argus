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
const { createRepositories } = require('./repositories');
const { createMonitorValidation, createGroupValidation, createStatusPageValidation } = require('./validation');
const { createStructuredLogger } = require('./observability/logger');
const { buildDashboardSnapshot, monitorTarget } = require('./queries/dashboardSnapshot');
const { buildPublicStatusSnapshot, formatUptimePercent } = require('./queries/publicStatusSnapshot');
const { MonitorEngine } = require('./monitorEngine');
const { sendWebhookAlert } = require('./alerts');
const { clampNumber, isLikelyUrl, normalizeUrl, safeLower } = require('./utils');
const { registerAuthRoutes } = require('./routes/auth');
const { registerMonitorRoutes } = require('./routes/monitors');
const { registerGroupRoutes } = require('./routes/groups');
const { registerStatusPageRoutes } = require('./routes/statusPages');

const app = express();
const baseStore = new DataStore(config.dbFile, config.retentionDays);
const store = createRepositories(baseStore);
const logger = createStructuredLogger(console, { app: config.appName });

const monitorValidation = createMonitorValidation({
  store,
  config,
  clampNumber,
  isLikelyUrl,
  normalizeUrl,
  safeLower
});
const groupValidation = createGroupValidation({
  normalizeUrl,
  safeLower,
  isLikelyUrl
});
const statusPageValidation = createStatusPageValidation();
const { parseMonitorForm, normalizeApiMonitorBody } = monitorValidation;
const { parseGroupForm } = groupValidation;
const { parseStatusPageForm } = statusPageValidation;

const engine = new MonitorEngine({
  store,
  normalIntervalMs: config.normalIntervalMs,
  downIntervalMs: config.downIntervalMs,
  confirmationRetries: config.confirmationRetries,
  confirmationRetryIntervalMs: config.confirmationRetryIntervalMs,
  minDowntimeBeforeAlertMs: config.minDowntimeBeforeAlertMs,
  alertCooldownMs: config.alertCooldownMs,
  keywordMinDowntimeMs: config.keywordMinDowntimeMs,
  logger
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
    minDowntimeMs: monitor.minDowntimeMs,
    alertCooldownMs: monitor.alertCooldownMs,
    active: monitor.active,
    statusClass,
    displayStatus,
    runtime: monitor.runtime,
    uptimePercent: formatUptimePercent(uptimeRatio),
    uptimeRatio
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

const apiRouter = express.Router();
apiRouter.use(requireApiKey);

registerAuthRoutes(app, {
  store,
  config,
  bcrypt,
  speakeasy,
  QRCode,
  asyncHandler,
  setFlash,
  clearSetupSecret,
  regenerateSession,
  saveSession,
  sessionCookieName,
  sessionCookieOptions
});

registerMonitorRoutes(app, apiRouter, {
  store,
  engine,
  config,
  asyncHandler,
  requireAuth,
  setFlash,
  monitorTarget,
  parseMonitorForm,
  sendManualStatusAlert,
  normalizeApiMonitorBody,
  serializeMonitorForApi,
  apiError
});

registerGroupRoutes(app, apiRouter, {
  store,
  asyncHandler,
  requireAuth,
  setFlash,
  parseGroupForm,
  sendManualStatusAlert,
  apiError
});

registerStatusPageRoutes(app, apiRouter, {
  store,
  asyncHandler,
  requireAuth,
  setFlash,
  parseStatusPageForm,
  apiError
});

app.use('/api/v1', apiRouter);

app.get('/healthz', (_req, res) => {
  res.status(200).json({
    ok: true,
    now: new Date().toISOString()
  });
});

app.get('/status/:slug', (req, res) => {
  const snapshot = buildPublicStatusSnapshot(store, req.params.slug);
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
  const snapshot = buildPublicStatusSnapshot(store, req.params.slug);
  if (!snapshot) {
    res.status(404).json({
      error: 'Status page not found'
    });
    return;
  }

  res.json(snapshot);
});

app.get(
  '/',
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = req.authenticatedUser.id;
    const snapshot = buildDashboardSnapshot(store, {
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
    const snapshot = buildDashboardSnapshot(store, {
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
  logger.error('server_error', error);

  res.status(500).render('error', {
    errorMessage: 'An unexpected error occurred.'
  });
});

const server = app.listen(config.port, () => {
  logger.info('server_listening', {
    port: config.port
  });
});

function gracefulShutdown(signal) {
  logger.info('server_shutdown_requested', {
    signal
  });

  engine.stop();

  server.close(() => {
    baseStore.close();
    process.exit(0);
  });
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
