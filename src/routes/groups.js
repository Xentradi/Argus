function registerGroupRoutes(app, apiRouter, {
  store,
  asyncHandler,
  requireAuth,
  setFlash,
  parseGroupForm,
  sendManualStatusAlert,
  apiError
}) {
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
}

module.exports = {
  registerGroupRoutes
};
