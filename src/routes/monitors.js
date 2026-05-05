function registerMonitorRoutes(app, apiRouter, {
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
}) {
  app.get('/monitors/new', requireAuth, (req, res) => {
    const groups = store.listGroups(req.authenticatedUser.id);
    res.render('monitor-form', {
      editing: false,
      groups,
      minDowntimeDefaultMs: config.minDowntimeBeforeAlertMs,
      alertCooldownDefaultMs: config.alertCooldownMs,
      keywordMinDowntimeMs: config.keywordMinDowntimeMs,
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
        minDowntimeMs: null,
        alertCooldownMs: null,
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
      minDowntimeDefaultMs: config.minDowntimeBeforeAlertMs,
      alertCooldownDefaultMs: config.alertCooldownMs,
      keywordMinDowntimeMs: config.keywordMinDowntimeMs,
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
}

module.exports = {
  registerMonitorRoutes
};
