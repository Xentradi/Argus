const crypto = require('crypto');
const { nowIso, rowToEvent } = require('./shared');

function createEventsRepository(db, retentionDays = 30) {
  return {
    addEvent: ({ userId = null, monitorId = null, monitorName = null, eventType, message, details = null }) => {
      const event = {
        id: crypto.randomUUID(),
        userId: userId || null,
        monitorId,
        monitorName,
        eventType,
        message,
        details,
        createdAt: nowIso()
      };

      db
        .prepare(
          `
            INSERT INTO events (id, user_id, monitor_id, monitor_name, event_type, message, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `
        )
        .run(
          event.id,
          event.userId,
          event.monitorId,
          event.monitorName,
          event.eventType,
          event.message,
          event.details ? JSON.stringify(event.details) : null,
          event.createdAt
        );

      return event;
    },
    countEvents: (userId = null) => {
      const row = userId
        ? db.prepare('SELECT COUNT(*) AS count FROM events WHERE user_id = ?').get(userId)
        : db.prepare('SELECT COUNT(*) AS count FROM events').get();
      return Number(row.count || 0);
    },
    listEvents: (limit = 200, offset = 0, userId = null) => {
      const rows = userId
        ? db
            .prepare(
              `
                SELECT id, user_id, monitor_id, monitor_name, event_type, message, details_json, created_at
                FROM events
                WHERE user_id = ?
                ORDER BY datetime(created_at) DESC
                LIMIT ?
                OFFSET ?
              `
            )
            .all(userId, limit, offset)
        : db
            .prepare(
              `
                SELECT id, user_id, monitor_id, monitor_name, event_type, message, details_json, created_at
                FROM events
                ORDER BY datetime(created_at) DESC
                LIMIT ?
                OFFSET ?
              `
            )
            .all(limit, offset);

      return rows.map((row) => rowToEvent(row));
    },
    pruneOldHistory: () => {
      const cutoffMs = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
      const cutoffIso = new Date(cutoffMs).toISOString();

      const deletedIncidents = db
        .prepare('DELETE FROM incidents WHERE ended_at IS NOT NULL AND datetime(ended_at) < datetime(?)')
        .run(cutoffIso).changes;

      const deletedEvents = db
        .prepare('DELETE FROM events WHERE datetime(created_at) < datetime(?)')
        .run(cutoffIso).changes;

      return {
        deletedIncidents,
        deletedEvents,
        cutoffIso
      };
    }
  };
}

module.exports = {
  createEventsRepository
};
