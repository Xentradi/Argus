function registerStatusPageRoutes(app, apiRouter, {
  store,
  asyncHandler,
  requireAuth,
  setFlash,
  parseStatusPageForm,
  apiError
}) {
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
}

module.exports = {
  registerStatusPageRoutes
};
