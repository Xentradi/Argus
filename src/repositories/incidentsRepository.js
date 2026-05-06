const crypto = require('crypto');
const { nowIso, rowToIncident } = require('./shared');

function createIncidentsRepository(db, monitorsRepository = null) {
  function getMonitorById(monitorId, userId = null) {
    if (monitorsRepository && typeof monitorsRepository.getMonitorById === 'function') {
      return monitorsRepository.getMonitorById(monitorId, userId);
    }

    const row = userId
      ? db.prepare('SELECT * FROM monitors WHERE id = ? AND user_id = ?').get(monitorId, userId)
      : db.prepare('SELECT * FROM monitors WHERE id = ?').get(monitorId);
    return row ? row : null;
  }

  function getOpenIncidentByMonitorId(monitorId) {
    const row = db
      .prepare(
        `
          SELECT * FROM incidents
          WHERE monitor_id = ? AND ended_at IS NULL
          ORDER BY datetime(started_at) DESC
          LIMIT 1
        `
      )
      .get(monitorId);
    return row ? rowToIncident(row) : null;
  }

  function listIncidents(limit = 100, userId = null) {
    const rows = userId
      ? db
          .prepare(
            `
              SELECT * FROM incidents
              WHERE user_id = ?
              ORDER BY datetime(started_at) DESC
              LIMIT ?
            `
          )
          .all(userId, limit)
      : db
          .prepare(
            `
              SELECT * FROM incidents
              ORDER BY datetime(started_at) DESC
              LIMIT ?
            `
          )
          .all(limit);

    return rows.map((row) => rowToIncident(row));
  }

  function listOpenIncidents(userId = null) {
    const rows = userId
      ? db
          .prepare(
            `
              SELECT * FROM incidents
              WHERE ended_at IS NULL AND user_id = ?
              ORDER BY datetime(started_at) DESC
            `
          )
          .all(userId)
      : db
          .prepare(
            `
              SELECT * FROM incidents
              WHERE ended_at IS NULL
              ORDER BY datetime(started_at) DESC
            `
          )
          .all();

    return rows.map((row) => rowToIncident(row));
  }

  function addIncident({ userId = null, monitorId, monitorName, startedAt, downReason }) {
    const incident = {
      id: crypto.randomUUID(),
      userId: userId || null,
      monitorId,
      monitorName,
      startedAt,
      endedAt: null,
      durationSeconds: null,
      downReason,
      recoveryReason: null,
      alertedAt: null,
      createdAt: nowIso(),
      updatedAt: nowIso()
    };

    db
      .prepare(
        `
          INSERT INTO incidents (
            id, user_id, monitor_id, monitor_name, started_at, ended_at,
            duration_seconds, down_reason, recovery_reason, alerted_at,
            created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `
      )
      .run(
        incident.id,
        incident.userId,
        incident.monitorId,
        incident.monitorName,
        incident.startedAt,
        incident.endedAt,
        incident.durationSeconds,
        incident.downReason,
        incident.recoveryReason,
        incident.alertedAt,
        incident.createdAt,
        incident.updatedAt
      );

    return incident;
  }

  function closeIncident(incidentId, { endedAt, recoveryReason }) {
    const incident = db.prepare('SELECT * FROM incidents WHERE id = ?').get(incidentId);
    if (!incident) {
      return null;
    }

    if (incident.ended_at) {
      return rowToIncident(incident);
    }

    const startedMs = new Date(incident.started_at).getTime();
    const endedMs = new Date(endedAt).getTime();
    const durationSeconds =
      Number.isFinite(startedMs) && Number.isFinite(endedMs) && endedMs >= startedMs
        ? Math.round((endedMs - startedMs) / 1000)
        : null;

    const updatedAt = nowIso();

    db
      .prepare(
        `
          UPDATE incidents
          SET ended_at = ?, recovery_reason = ?, duration_seconds = ?, updated_at = ?
          WHERE id = ?
        `
      )
      .run(endedAt, recoveryReason, durationSeconds, updatedAt, incidentId);

    return {
      ...rowToIncident(incident),
      endedAt,
      durationSeconds,
      recoveryReason,
      updatedAt
    };
  }

  function markIncidentAlerted(incidentId, alertedAt) {
    const incident = db.prepare('SELECT * FROM incidents WHERE id = ?').get(incidentId);
    if (!incident) {
      return null;
    }

    const updatedAt = nowIso();
    db
      .prepare(
        `
          UPDATE incidents
          SET alerted_at = ?, updated_at = ?
          WHERE id = ?
        `
      )
      .run(alertedAt, updatedAt, incidentId);

    return {
      ...rowToIncident(incident),
      alertedAt,
      updatedAt
    };
  }

  function closeOpenIncidentForMonitor(monitorId, details) {
    const incident = getOpenIncidentByMonitorId(monitorId);
    if (!incident) {
      return null;
    }

    return closeIncident(incident.id, details);
  }

  function getLatestRecoveryTimesByMonitorIds(monitorIds) {
    const ids = Array.from(new Set((Array.isArray(monitorIds) ? monitorIds : []).map((id) => String(id || '').trim()).filter(Boolean)));
    if (ids.length === 0) {
      return {};
    }

    const placeholders = ids.map(() => '?').join(', ');
    const rows = db
      .prepare(
        `
          SELECT monitor_id, MAX(ended_at) AS last_recovery_at
          FROM incidents
          WHERE ended_at IS NOT NULL
            AND monitor_id IN (${placeholders})
          GROUP BY monitor_id
        `
      )
      .all(...ids);

    const recoveryTimesByMonitorId = {};
    for (const row of rows) {
      if (!row.monitor_id || !row.last_recovery_at) {
        continue;
      }
      recoveryTimesByMonitorId[row.monitor_id] = row.last_recovery_at;
    }

    return recoveryTimesByMonitorId;
  }

  function calculateMonitorUptimeStats(monitorId, at = nowIso(), userId = null) {
    const monitor = getMonitorById(monitorId, userId);
    if (!monitor) {
      return null;
    }

    const endMsRaw = new Date(at).getTime();
    const endMs = Number.isFinite(endMsRaw) ? endMsRaw : Date.now();

    const startMsRaw = new Date(monitor.createdAt).getTime();
    const startMs = Number.isFinite(startMsRaw) ? Math.min(startMsRaw, endMs) : endMs;

    const startIso = new Date(startMs).toISOString();
    const endIso = new Date(endMs).toISOString();

    const incidentRows = db
      .prepare(
        `
          SELECT started_at, ended_at
          FROM incidents
          WHERE monitor_id = ?
            AND datetime(started_at) <= datetime(?)
            AND (ended_at IS NULL OR datetime(ended_at) >= datetime(?))
          ORDER BY datetime(started_at) ASC
        `
      )
      .all(monitorId, endIso, startIso);

    let downtimeMs = 0;

    for (const row of incidentRows) {
      const incidentStartMs = new Date(row.started_at).getTime();
      if (!Number.isFinite(incidentStartMs)) {
        continue;
      }

      const incidentEndMsRaw = row.ended_at ? new Date(row.ended_at).getTime() : endMs;
      const incidentEndMs = Number.isFinite(incidentEndMsRaw) ? incidentEndMsRaw : endMs;

      const overlapStart = Math.max(startMs, incidentStartMs);
      const overlapEnd = Math.min(endMs, incidentEndMs);
      if (overlapEnd > overlapStart) {
        downtimeMs += overlapEnd - overlapStart;
      }
    }

    const totalMs = Math.max(0, endMs - startMs);
    if (downtimeMs > totalMs) {
      downtimeMs = totalMs;
    }

    const uptimeRatio = totalMs === 0 ? 1 : (totalMs - downtimeMs) / totalMs;

    return {
      monitorId,
      windowStartAt: startIso,
      windowEndAt: endIso,
      totalMs,
      downtimeMs,
      uptimeRatio
    };
  }

  return {
    listIncidents,
    listOpenIncidents,
    addIncident,
    getOpenIncidentByMonitorId,
    closeIncident,
    markIncidentAlerted,
    closeOpenIncidentForMonitor,
    getLatestRecoveryTimesByMonitorIds,
    calculateMonitorUptimeStats
  };
}

module.exports = {
  createIncidentsRepository
};
