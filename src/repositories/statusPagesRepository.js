const crypto = require('crypto');
const { nowIso, resolveOwnerUserId, rowToStatusPage, rowToMonitor } = require('./shared');

function createStatusPagesRepository(db) {
  function listMonitorsForStatusPage(statusPageId) {
    const rows = db
      .prepare(
        `
          SELECT m.*
          FROM status_page_monitors spm
          INNER JOIN monitors m ON m.id = spm.monitor_id
          WHERE spm.status_page_id = ?
          ORDER BY
            CASE WHEN m.group_id IS NULL THEN 1 ELSE 0 END ASC,
            lower(m.group_name) ASC,
            m.sort_order ASC,
            lower(m.name) ASC,
            datetime(m.created_at) ASC
        `
      )
      .all(statusPageId);

    return rows.map((row) => rowToMonitor(row));
  }

  function getStatusPageById(id, userId = null) {
    const row = userId
      ? db
          .prepare('SELECT id, user_id, name, slug, created_at, updated_at FROM status_pages WHERE id = ? AND user_id = ?')
          .get(id, userId)
      : db
          .prepare('SELECT id, user_id, name, slug, created_at, updated_at FROM status_pages WHERE id = ?')
          .get(id);
    if (!row) {
      return null;
    }

    const page = rowToStatusPage(row);
    const monitors = listMonitorsForStatusPage(page.id);

    return {
      ...page,
      monitors,
      monitorCount: monitors.length
    };
  }

  return {
    listStatusPages: (userId = null) => {
      const rows = userId
        ? db
            .prepare(
              `
                SELECT sp.id, sp.user_id, sp.name, sp.slug, sp.created_at, sp.updated_at, COUNT(spm.monitor_id) AS monitor_count
                FROM status_pages sp
                LEFT JOIN status_page_monitors spm ON spm.status_page_id = sp.id
                WHERE sp.user_id = ?
                GROUP BY sp.id
                ORDER BY lower(sp.name) ASC, datetime(sp.created_at) ASC
              `
            )
            .all(userId)
        : db
            .prepare(
              `
                SELECT sp.id, sp.user_id, sp.name, sp.slug, sp.created_at, sp.updated_at, COUNT(spm.monitor_id) AS monitor_count
                FROM status_pages sp
                LEFT JOIN status_page_monitors spm ON spm.status_page_id = sp.id
                GROUP BY sp.id
                ORDER BY lower(sp.name) ASC, datetime(sp.created_at) ASC
              `
            )
            .all();

      return rows.map((row) => ({
        ...rowToStatusPage(row),
        monitorCount: Number(row.monitor_count || 0)
      }));
    },
    listMonitorsForStatusPage,
    getStatusPageById,
    getStatusPageBySlug: (slug, userId = null) => {
      const normalizedSlug = String(slug || '').trim().toLowerCase();
      if (!normalizedSlug) {
        return null;
      }

      const row = userId
        ? db
            .prepare(
              'SELECT id, user_id, name, slug, created_at, updated_at FROM status_pages WHERE lower(slug) = lower(?) AND user_id = ? LIMIT 1'
            )
            .get(normalizedSlug, userId)
        : db
            .prepare('SELECT id, user_id, name, slug, created_at, updated_at FROM status_pages WHERE lower(slug) = lower(?) LIMIT 1')
            .get(normalizedSlug);

      if (!row) {
        return null;
      }

      return getStatusPageById(row.id, userId);
    },
    createStatusPage: ({ userId, name, slug, monitorIds }) => {
      const trimmedUserId = resolveOwnerUserId(db, userId);

      const trimmedName = String(name || '').trim();
      const normalizedSlug = String(slug || '').trim().toLowerCase();

      if (!trimmedName) {
        throw new Error('Status page name is required.');
      }

      if (!normalizedSlug) {
        throw new Error('Status page slug is required.');
      }

      const slugConflict = db
        .prepare('SELECT id FROM status_pages WHERE lower(slug) = lower(?) LIMIT 1')
        .get(normalizedSlug);
      if (slugConflict) {
        throw new Error('Status page slug already exists.');
      }

      const requestedMonitorIds = Array.from(
        new Set((Array.isArray(monitorIds) ? monitorIds : []).map((id) => String(id || '').trim()).filter(Boolean))
      );

      if (requestedMonitorIds.length === 0) {
        throw new Error('Select at least one monitor.');
      }

      const placeholders = requestedMonitorIds.map(() => '?').join(', ');
      const monitorRows = trimmedUserId
        ? db
            .prepare(`SELECT id FROM monitors WHERE user_id = ? AND id IN (${placeholders})`)
            .all(trimmedUserId, ...requestedMonitorIds)
        : db
            .prepare(`SELECT id FROM monitors WHERE id IN (${placeholders})`)
            .all(...requestedMonitorIds);
      const validIds = new Set(monitorRows.map((row) => row.id));
      const selectedMonitorIds = requestedMonitorIds.filter((id) => validIds.has(id));

      if (selectedMonitorIds.length === 0) {
        throw new Error('No valid monitors were selected.');
      }

      const now = nowIso();
      const statusPage = {
        id: crypto.randomUUID(),
        userId: trimmedUserId,
        name: trimmedName,
        slug: normalizedSlug,
        createdAt: now,
        updatedAt: now
      };

      const create = db.transaction(() => {
        db
          .prepare(
            `
              INSERT INTO status_pages (id, user_id, name, slug, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, ?)
            `
          )
          .run(statusPage.id, statusPage.userId, statusPage.name, statusPage.slug, statusPage.createdAt, statusPage.updatedAt);

        const insertMonitor = db.prepare(
          `
            INSERT INTO status_page_monitors (status_page_id, monitor_id, created_at)
            VALUES (?, ?, ?)
          `
        );

        selectedMonitorIds.forEach((monitorId) => {
          insertMonitor.run(statusPage.id, monitorId, now);
        });
      });

      create();
      return getStatusPageById(statusPage.id, trimmedUserId);
    },
    deleteStatusPage: (id, userId = null) => {
      const existing = getStatusPageById(id, userId);
      if (!existing) {
        return null;
      }

      if (existing.userId) {
        db.prepare('DELETE FROM status_pages WHERE id = ? AND user_id = ?').run(id, existing.userId);
      } else {
        db.prepare('DELETE FROM status_pages WHERE id = ?').run(id);
      }
      return existing;
    }
  };
}

module.exports = {
  createStatusPagesRepository
};
