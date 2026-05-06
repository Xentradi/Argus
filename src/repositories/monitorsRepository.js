const crypto = require('crypto');
const { nowIso, resolveOwnerUserId, rowToMonitor, toIntegerBoolean } = require('./shared');

function createMonitorsRepository(db) {
  function getMonitorRow(id, userId = null) {
    return userId
      ? db.prepare('SELECT * FROM monitors WHERE id = ? AND user_id = ?').get(id, userId)
      : db.prepare('SELECT * FROM monitors WHERE id = ?').get(id);
  }

  function getNextMonitorSortOrder(groupId, userId = null) {
    if (groupId) {
      const row = userId
        ? db
            .prepare('SELECT COALESCE(MAX(sort_order), 0) AS max_sort_order FROM monitors WHERE group_id = ? AND user_id = ?')
            .get(groupId, userId)
        : db
            .prepare('SELECT COALESCE(MAX(sort_order), 0) AS max_sort_order FROM monitors WHERE group_id = ?')
            .get(groupId);
      return Number(row.max_sort_order || 0) + 1;
    }

    const row = userId
      ? db
          .prepare('SELECT COALESCE(MAX(sort_order), 0) AS max_sort_order FROM monitors WHERE group_id IS NULL AND user_id = ?')
          .get(userId)
      : db
          .prepare('SELECT COALESCE(MAX(sort_order), 0) AS max_sort_order FROM monitors WHERE group_id IS NULL')
          .get();
    return Number(row.max_sort_order || 0) + 1;
  }

  function updateMonitor(id, patch, userId = null) {
    const current = getMonitorRow(id, userId);
    if (!current) {
      return null;
    }

    const currentMonitor = rowToMonitor(current);
    const targetGroupId = patch.groupId !== undefined ? patch.groupId || null : currentMonitor.groupId;
    const groupChanged = targetGroupId !== currentMonitor.groupId;
    const sortOrder =
      patch.sortOrder !== undefined
        ? Number(patch.sortOrder)
        : groupChanged
          ? getNextMonitorSortOrder(targetGroupId, currentMonitor.userId)
          : currentMonitor.sortOrder;

    const next = {
      ...currentMonitor,
      ...patch,
      groupId: targetGroupId,
      groupName: String(patch.groupName !== undefined ? patch.groupName : currentMonitor.groupName).trim(),
      sortOrder: Number.isFinite(sortOrder) ? sortOrder : currentMonitor.sortOrder,
      runtime: {
        ...currentMonitor.runtime,
        ...(patch.runtime || {})
      },
      updatedAt: nowIso()
    };

    const updateValues = [
      next.name,
      next.groupName,
      next.groupId,
      next.sortOrder,
      next.checkType,
      next.host,
      next.url,
      next.keyword,
      toIntegerBoolean(next.keywordCaseSensitive),
      next.httpStatusMode,
      toIntegerBoolean(next.tlsErrorAsFailure),
      next.webhookType,
      next.webhookUrl,
      next.timeoutMs,
      next.minDowntimeMs === undefined ? null : next.minDowntimeMs,
      next.alertCooldownMs === undefined ? null : next.alertCooldownMs,
      toIntegerBoolean(next.active),
      next.updatedAt,
      next.runtime.status,
      next.runtime.lastCheckAt,
      next.runtime.firstSuccessAt,
      next.runtime.lastSuccessAt,
      next.runtime.lastFailureAt,
      next.runtime.lastError,
      next.runtime.lastResponseMs,
      next.runtime.lastHttpStatus,
      next.runtime.lastKeywordMatched === null ? null : toIntegerBoolean(next.runtime.lastKeywordMatched),
      toIntegerBoolean(next.runtime.lastTlsError),
      next.runtime.lastAlertDownAt,
      next.runtime.nextCheckAt,
      id
    ];

    if (currentMonitor.userId) {
      db
        .prepare(
          `
            UPDATE monitors
            SET
              name = ?,
              group_name = ?,
              group_id = ?,
              sort_order = ?,
              check_type = ?,
              host = ?,
              url = ?,
              keyword = ?,
              keyword_case_sensitive = ?,
              http_status_mode = ?,
              tls_error_as_failure = ?,
              webhook_type = ?,
              webhook_url = ?,
              timeout_ms = ?,
              min_downtime_ms = ?,
              alert_cooldown_ms = ?,
              active = ?,
              updated_at = ?,
              status = ?,
              last_check_at = ?,
              first_success_at = ?,
              last_success_at = ?,
              last_failure_at = ?,
              last_error = ?,
              last_response_ms = ?,
              last_http_status = ?,
              last_keyword_matched = ?,
              last_tls_error = ?,
              last_alert_down_at = ?,
              next_check_at = ?
            WHERE id = ? AND user_id = ?
          `
        )
        .run(...updateValues, currentMonitor.userId);
    } else {
      db
        .prepare(
          `
            UPDATE monitors
            SET
              name = ?,
              group_name = ?,
              group_id = ?,
              sort_order = ?,
              check_type = ?,
              host = ?,
              url = ?,
              keyword = ?,
              keyword_case_sensitive = ?,
              http_status_mode = ?,
              tls_error_as_failure = ?,
              webhook_type = ?,
              webhook_url = ?,
              timeout_ms = ?,
              min_downtime_ms = ?,
              alert_cooldown_ms = ?,
              active = ?,
              updated_at = ?,
              status = ?,
              last_check_at = ?,
              first_success_at = ?,
              last_success_at = ?,
              last_failure_at = ?,
              last_error = ?,
              last_response_ms = ?,
              last_http_status = ?,
              last_keyword_matched = ?,
              last_tls_error = ?,
              last_alert_down_at = ?,
              next_check_at = ?
            WHERE id = ?
          `
        )
        .run(...updateValues);
    }

    return rowToMonitor(getMonitorRow(id, currentMonitor.userId));
  }

  return {
    listMonitors: (userId = null) => {
      const rows = userId
        ? db
            .prepare(
              `
                SELECT * FROM monitors
                WHERE user_id = ?
                ORDER BY
                  CASE WHEN group_id IS NULL THEN 1 ELSE 0 END ASC,
                  lower(group_name) ASC,
                  sort_order ASC,
                  lower(name) ASC,
                  datetime(created_at) ASC
              `
            )
            .all(userId)
        : db
            .prepare(
              `
                SELECT * FROM monitors
                ORDER BY
                  CASE WHEN group_id IS NULL THEN 1 ELSE 0 END ASC,
                  lower(group_name) ASC,
                  sort_order ASC,
                  lower(name) ASC,
                  datetime(created_at) ASC
              `
            )
            .all();

      return rows.map((row) => rowToMonitor(row));
    },
    getMonitorById: (id, userId = null) => {
      const row = getMonitorRow(id, userId);
      return row ? rowToMonitor(row) : null;
    },
    getNextMonitorSortOrder,
    createMonitor: (payload) => {
      const now = nowIso();
      const groupId = payload.groupId || null;
      const userId = resolveOwnerUserId(db, payload.userId);

      const monitor = {
        id: crypto.randomUUID(),
        userId,
        name: payload.name || 'Unnamed monitor',
        groupId,
        groupName: String(payload.groupName || '').trim(),
        sortOrder: Number.isFinite(Number(payload.sortOrder))
          ? Number(payload.sortOrder)
          : getNextMonitorSortOrder(groupId, userId),
        checkType: payload.checkType || 'http',
        host: payload.host || '',
        url: payload.url || '',
        keyword: payload.keyword || '',
        keywordCaseSensitive: Boolean(payload.keywordCaseSensitive),
        httpStatusMode: payload.httpStatusMode || '2xx',
        tlsErrorAsFailure: payload.tlsErrorAsFailure !== false,
        webhookType: payload.webhookType || 'slack',
        webhookUrl: payload.webhookUrl || '',
        timeoutMs: Number(payload.timeoutMs) || 10000,
        minDowntimeMs:
          payload.minDowntimeMs === null || payload.minDowntimeMs === undefined ? null : Number(payload.minDowntimeMs),
        alertCooldownMs:
          payload.alertCooldownMs === null || payload.alertCooldownMs === undefined ? null : Number(payload.alertCooldownMs),
        active: payload.active !== false,
        createdAt: now,
        updatedAt: now,
        runtime: {
          status: 'unknown',
          lastCheckAt: null,
          firstSuccessAt: null,
          lastSuccessAt: null,
          lastFailureAt: null,
          lastError: null,
          lastResponseMs: null,
          lastHttpStatus: null,
          lastKeywordMatched: null,
          lastTlsError: false,
          lastAlertDownAt: null,
          nextCheckAt: null
        }
      };

      db
        .prepare(
          `
            INSERT INTO monitors (
              id, user_id, name, group_name, group_id, sort_order, check_type, host, url, keyword,
              keyword_case_sensitive, http_status_mode, tls_error_as_failure,
              webhook_type, webhook_url, timeout_ms, min_downtime_ms, alert_cooldown_ms, active,
              created_at, updated_at,
              status, last_check_at, first_success_at, last_success_at, last_failure_at,
              last_error, last_response_ms, last_http_status,
              last_keyword_matched, last_tls_error, last_alert_down_at, next_check_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `
        )
        .run(
          monitor.id,
          monitor.userId,
          monitor.name,
          monitor.groupName,
          monitor.groupId,
          monitor.sortOrder,
          monitor.checkType,
          monitor.host,
          monitor.url,
          monitor.keyword,
          toIntegerBoolean(monitor.keywordCaseSensitive),
          monitor.httpStatusMode,
          toIntegerBoolean(monitor.tlsErrorAsFailure),
          monitor.webhookType,
          monitor.webhookUrl,
          monitor.timeoutMs,
          monitor.minDowntimeMs,
          monitor.alertCooldownMs,
          toIntegerBoolean(monitor.active),
          monitor.createdAt,
          monitor.updatedAt,
          monitor.runtime.status,
          monitor.runtime.lastCheckAt,
          monitor.runtime.firstSuccessAt,
          monitor.runtime.lastSuccessAt,
          monitor.runtime.lastFailureAt,
          monitor.runtime.lastError,
          monitor.runtime.lastResponseMs,
          monitor.runtime.lastHttpStatus,
          monitor.runtime.lastKeywordMatched === null ? null : toIntegerBoolean(monitor.runtime.lastKeywordMatched),
          toIntegerBoolean(monitor.runtime.lastTlsError),
          monitor.runtime.lastAlertDownAt,
          monitor.runtime.nextCheckAt
        );

      return monitor;
    },
    updateMonitor,
    updateMonitorRuntime: (id, runtimePatch) => {
      const current = rowToMonitor(getMonitorRow(id));
      if (!current) {
        return null;
      }

      return updateMonitor(id, {
        runtime: {
          ...current.runtime,
          ...runtimePatch
        }
      }, current.userId);
    },
    deleteMonitor: (id, userId = null) => {
      const existing = getMonitorRow(id, userId);
      if (!existing) {
        return null;
      }

      if (existing.user_id) {
        db.prepare('DELETE FROM monitors WHERE id = ? AND user_id = ?').run(id, existing.user_id);
      } else {
        db.prepare('DELETE FROM monitors WHERE id = ?').run(id);
      }
      return rowToMonitor(existing);
    },
    moveMonitorInGroup: (id, direction, userId = null) => {
      const monitor = rowToMonitor(getMonitorRow(id, userId));
      if (!monitor) {
        return null;
      }

      const rows = monitor.groupId
        ? monitor.userId
          ? db
              .prepare(
                `
                  SELECT id, sort_order, created_at, name
                  FROM monitors
                  WHERE group_id = ? AND user_id = ?
                  ORDER BY sort_order ASC, datetime(created_at) ASC, lower(name) ASC
                `
              )
              .all(monitor.groupId, monitor.userId)
          : db
              .prepare(
                `
                  SELECT id, sort_order, created_at, name
                  FROM monitors
                  WHERE group_id = ?
                  ORDER BY sort_order ASC, datetime(created_at) ASC, lower(name) ASC
                `
              )
              .all(monitor.groupId)
        : monitor.userId
          ? db
              .prepare(
                `
                  SELECT id, sort_order, created_at, name
                  FROM monitors
                  WHERE group_id IS NULL AND user_id = ?
                  ORDER BY sort_order ASC, datetime(created_at) ASC, lower(name) ASC
                `
              )
              .all(monitor.userId)
          : db
              .prepare(
                `
                  SELECT id, sort_order, created_at, name
                  FROM monitors
                  WHERE group_id IS NULL
                  ORDER BY sort_order ASC, datetime(created_at) ASC, lower(name) ASC
                `
              )
              .all();

      if (rows.length < 2) {
        return monitor;
      }

      const normalize = db.transaction(() => {
        const update = db.prepare('UPDATE monitors SET sort_order = ?, updated_at = ? WHERE id = ?');
        rows.forEach((row, index) => {
          update.run(index + 1, nowIso(), row.id);
        });
      });
      normalize();

      const normalizedRows = monitor.groupId
        ? monitor.userId
          ? db
              .prepare(
                `
                  SELECT id, sort_order
                  FROM monitors
                  WHERE group_id = ? AND user_id = ?
                  ORDER BY sort_order ASC
                `
              )
              .all(monitor.groupId, monitor.userId)
          : db
              .prepare(
                `
                  SELECT id, sort_order
                  FROM monitors
                  WHERE group_id = ?
                  ORDER BY sort_order ASC
                `
              )
              .all(monitor.groupId)
        : monitor.userId
          ? db
              .prepare(
                `
                  SELECT id, sort_order
                  FROM monitors
                  WHERE group_id IS NULL AND user_id = ?
                  ORDER BY sort_order ASC
                `
              )
              .all(monitor.userId)
          : db
              .prepare(
                `
                  SELECT id, sort_order
                  FROM monitors
                  WHERE group_id IS NULL
                  ORDER BY sort_order ASC
                `
              )
              .all();

      const currentIndex = normalizedRows.findIndex((row) => row.id === id);
      if (currentIndex < 0) {
        return rowToMonitor(getMonitorRow(id, monitor.userId));
      }

      const targetIndex = direction === 'up' ? currentIndex - 1 : currentIndex + 1;
      if (targetIndex < 0 || targetIndex >= normalizedRows.length) {
        return rowToMonitor(getMonitorRow(id, monitor.userId));
      }

      const currentRow = normalizedRows[currentIndex];
      const targetRow = normalizedRows[targetIndex];

      const swap = db.transaction(() => {
        const now = nowIso();
        const update = db.prepare('UPDATE monitors SET sort_order = ?, updated_at = ? WHERE id = ?');
        update.run(targetRow.sort_order, now, currentRow.id);
        update.run(currentRow.sort_order, now, targetRow.id);
      });

      swap();
      return rowToMonitor(getMonitorRow(id, monitor.userId));
    }
  };
}

module.exports = {
  createMonitorsRepository
};
