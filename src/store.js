const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

function nowIso() {
  return new Date().toISOString();
}

function toIntegerBoolean(value) {
  return value ? 1 : 0;
}

function fromIntegerBoolean(value) {
  return Number(value) === 1;
}

class DataStore {
  constructor(dbFile, retentionDays) {
    this.dbFile = dbFile;
    this.retentionDays = retentionDays;

    fs.mkdirSync(path.dirname(dbFile), { recursive: true });

    this.db = new Database(dbFile);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');

    this.initializeSchema();
    this.pruneOldHistory();
  }

  initializeSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        totp_secret TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS monitors (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        group_name TEXT NOT NULL DEFAULT 'Default',
        check_type TEXT NOT NULL,
        host TEXT NOT NULL DEFAULT '',
        url TEXT NOT NULL DEFAULT '',
        keyword TEXT NOT NULL DEFAULT '',
        keyword_case_sensitive INTEGER NOT NULL DEFAULT 0,
        http_status_mode TEXT NOT NULL DEFAULT '2xx',
        tls_error_as_failure INTEGER NOT NULL DEFAULT 1,
        webhook_type TEXT NOT NULL DEFAULT 'slack',
        webhook_url TEXT NOT NULL DEFAULT '',
        timeout_ms INTEGER NOT NULL DEFAULT 10000,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'unknown',
        last_check_at TEXT,
        last_success_at TEXT,
        last_failure_at TEXT,
        last_error TEXT,
        last_response_ms INTEGER,
        last_http_status INTEGER,
        last_keyword_matched INTEGER,
        last_tls_error INTEGER NOT NULL DEFAULT 0,
        next_check_at TEXT
      );

      CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        monitor_id TEXT NOT NULL,
        monitor_name TEXT NOT NULL,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        duration_seconds INTEGER,
        down_reason TEXT,
        recovery_reason TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_incidents_started_at ON incidents(started_at);
      CREATE INDEX IF NOT EXISTS idx_incidents_monitor_open ON incidents(monitor_id, ended_at);

      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        monitor_id TEXT,
        monitor_name TEXT,
        event_type TEXT NOT NULL,
        message TEXT NOT NULL,
        details_json TEXT,
        created_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
      CREATE INDEX IF NOT EXISTS idx_events_monitor ON events(monitor_id);
    `);

    this.migrateIncidentsTableIfNeeded();
    this.migrateMonitorsGroupColumnIfNeeded();
  }

  migrateIncidentsTableIfNeeded() {
    const foreignKeys = this.db.prepare("PRAGMA foreign_key_list('incidents')").all();
    if (foreignKeys.length === 0) {
      return;
    }

    const migrate = this.db.transaction(() => {
      this.db.exec(`
        CREATE TABLE incidents_new (
          id TEXT PRIMARY KEY,
          monitor_id TEXT NOT NULL,
          monitor_name TEXT NOT NULL,
          started_at TEXT NOT NULL,
          ended_at TEXT,
          duration_seconds INTEGER,
          down_reason TEXT,
          recovery_reason TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        INSERT INTO incidents_new (
          id, monitor_id, monitor_name, started_at, ended_at,
          duration_seconds, down_reason, recovery_reason, created_at, updated_at
        )
        SELECT
          id, monitor_id, monitor_name, started_at, ended_at,
          duration_seconds, down_reason, recovery_reason, created_at, updated_at
        FROM incidents;

        DROP TABLE incidents;
        ALTER TABLE incidents_new RENAME TO incidents;

        CREATE INDEX IF NOT EXISTS idx_incidents_started_at ON incidents(started_at);
        CREATE INDEX IF NOT EXISTS idx_incidents_monitor_open ON incidents(monitor_id, ended_at);
      `);
    });

    migrate();
  }

  migrateMonitorsGroupColumnIfNeeded() {
    const columns = this.db.prepare("PRAGMA table_info('monitors')").all();
    const hasGroupColumn = columns.some((column) => column.name === 'group_name');

    if (!hasGroupColumn) {
      this.db
        .prepare("ALTER TABLE monitors ADD COLUMN group_name TEXT NOT NULL DEFAULT 'Default'")
        .run();
    }
  }

  hasUsers() {
    const row = this.db.prepare('SELECT COUNT(*) AS count FROM users').get();
    return row.count > 0;
  }

  getMeta(key) {
    const row = this.db.prepare('SELECT value FROM meta WHERE key = ?').get(key);
    return row ? row.value : null;
  }

  setMeta(key, value) {
    this.db
      .prepare(
        `
          INSERT INTO meta(key, value) VALUES(?, ?)
          ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `
      )
      .run(key, value);
  }

  getSessionSecret() {
    const existing = this.getMeta('session_secret');
    if (existing) {
      return existing;
    }

    const generated = crypto.randomBytes(32).toString('hex');
    this.setMeta('session_secret', generated);
    return generated;
  }

  createUser({ username, passwordHash, totpSecret }) {
    const trimmed = String(username || '').trim();
    if (!trimmed) {
      throw new Error('Username is required.');
    }

    const existing = this.findUserByUsername(trimmed);
    if (existing) {
      throw new Error('Username already exists.');
    }

    const user = {
      id: crypto.randomUUID(),
      username: trimmed,
      passwordHash,
      totpSecret,
      createdAt: nowIso()
    };

    this.db
      .prepare(
        `
          INSERT INTO users (id, username, password_hash, totp_secret, created_at)
          VALUES (?, ?, ?, ?, ?)
        `
      )
      .run(user.id, user.username, user.passwordHash, user.totpSecret, user.createdAt);

    return user;
  }

  findUserByUsername(username) {
    const trimmed = String(username || '').trim();
    if (!trimmed) {
      return null;
    }

    const row = this.db
      .prepare('SELECT id, username, password_hash, totp_secret, created_at FROM users WHERE lower(username) = lower(?)')
      .get(trimmed);

    if (!row) {
      return null;
    }

    return {
      id: row.id,
      username: row.username,
      passwordHash: row.password_hash,
      totpSecret: row.totp_secret,
      createdAt: row.created_at
    };
  }

  findUserById(id) {
    const row = this.db
      .prepare('SELECT id, username, password_hash, totp_secret, created_at FROM users WHERE id = ?')
      .get(id);

    if (!row) {
      return null;
    }

    return {
      id: row.id,
      username: row.username,
      passwordHash: row.password_hash,
      totpSecret: row.totp_secret,
      createdAt: row.created_at
    };
  }

  rowToMonitor(row) {
    return {
      id: row.id,
      name: row.name,
      groupName: row.group_name || 'Default',
      checkType: row.check_type,
      host: row.host,
      url: row.url,
      keyword: row.keyword,
      keywordCaseSensitive: fromIntegerBoolean(row.keyword_case_sensitive),
      httpStatusMode: row.http_status_mode,
      tlsErrorAsFailure: fromIntegerBoolean(row.tls_error_as_failure),
      webhookType: row.webhook_type,
      webhookUrl: row.webhook_url,
      timeoutMs: row.timeout_ms,
      active: fromIntegerBoolean(row.active),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      runtime: {
        status: row.status,
        lastCheckAt: row.last_check_at,
        lastSuccessAt: row.last_success_at,
        lastFailureAt: row.last_failure_at,
        lastError: row.last_error,
        lastResponseMs: row.last_response_ms,
        lastHttpStatus: row.last_http_status,
        lastKeywordMatched:
          row.last_keyword_matched === null || row.last_keyword_matched === undefined
            ? null
            : fromIntegerBoolean(row.last_keyword_matched),
        lastTlsError: fromIntegerBoolean(row.last_tls_error),
        nextCheckAt: row.next_check_at
      }
    };
  }

  listMonitors() {
    const rows = this.db
      .prepare(
        `
          SELECT * FROM monitors
          ORDER BY datetime(created_at) DESC
        `
      )
      .all();

    return rows.map((row) => this.rowToMonitor(row));
  }

  getMonitorById(id) {
    const row = this.db.prepare('SELECT * FROM monitors WHERE id = ?').get(id);
    return row ? this.rowToMonitor(row) : null;
  }

  createMonitor(payload) {
    const now = nowIso();

    const monitor = {
      id: crypto.randomUUID(),
      name: payload.name || 'Unnamed monitor',
      groupName: String(payload.groupName || 'Default').trim() || 'Default',
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
      active: payload.active !== false,
      createdAt: now,
      updatedAt: now,
      runtime: {
        status: 'unknown',
        lastCheckAt: null,
        lastSuccessAt: null,
        lastFailureAt: null,
        lastError: null,
        lastResponseMs: null,
        lastHttpStatus: null,
        lastKeywordMatched: null,
        lastTlsError: false,
        nextCheckAt: null
      }
    };

    this.db
      .prepare(
        `
          INSERT INTO monitors (
            id, name, group_name, check_type, host, url, keyword,
            keyword_case_sensitive, http_status_mode, tls_error_as_failure,
            webhook_type, webhook_url, timeout_ms, active,
            created_at, updated_at,
            status, last_check_at, last_success_at, last_failure_at,
            last_error, last_response_ms, last_http_status,
            last_keyword_matched, last_tls_error, next_check_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `
      )
      .run(
        monitor.id,
        monitor.name,
        monitor.groupName,
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
        toIntegerBoolean(monitor.active),
        monitor.createdAt,
        monitor.updatedAt,
        monitor.runtime.status,
        monitor.runtime.lastCheckAt,
        monitor.runtime.lastSuccessAt,
        monitor.runtime.lastFailureAt,
        monitor.runtime.lastError,
        monitor.runtime.lastResponseMs,
        monitor.runtime.lastHttpStatus,
        monitor.runtime.lastKeywordMatched === null ? null : toIntegerBoolean(monitor.runtime.lastKeywordMatched),
        toIntegerBoolean(monitor.runtime.lastTlsError),
        monitor.runtime.nextCheckAt
      );

    return monitor;
  }

  updateMonitor(id, patch) {
    const current = this.getMonitorById(id);
    if (!current) {
      return null;
    }

    const next = {
      ...current,
      ...patch,
      runtime: {
        ...current.runtime,
        ...(patch.runtime || {})
      },
      updatedAt: nowIso()
    };

    this.db
      .prepare(
        `
          UPDATE monitors
          SET
            name = ?,
            group_name = ?,
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
            active = ?,
            updated_at = ?,
            status = ?,
            last_check_at = ?,
            last_success_at = ?,
            last_failure_at = ?,
            last_error = ?,
            last_response_ms = ?,
            last_http_status = ?,
            last_keyword_matched = ?,
            last_tls_error = ?,
            next_check_at = ?
          WHERE id = ?
        `
      )
      .run(
        next.name,
        next.groupName,
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
        toIntegerBoolean(next.active),
        next.updatedAt,
        next.runtime.status,
        next.runtime.lastCheckAt,
        next.runtime.lastSuccessAt,
        next.runtime.lastFailureAt,
        next.runtime.lastError,
        next.runtime.lastResponseMs,
        next.runtime.lastHttpStatus,
        next.runtime.lastKeywordMatched === null
          ? null
          : toIntegerBoolean(next.runtime.lastKeywordMatched),
        toIntegerBoolean(next.runtime.lastTlsError),
        next.runtime.nextCheckAt,
        id
      );

    return this.getMonitorById(id);
  }

  updateMonitorRuntime(id, runtimePatch) {
    return this.updateMonitor(id, {
      runtime: runtimePatch
    });
  }

  deleteMonitor(id) {
    const existing = this.getMonitorById(id);
    if (!existing) {
      return null;
    }

    this.db.prepare('DELETE FROM monitors WHERE id = ?').run(id);
    return existing;
  }

  listIncidents(limit = 100) {
    const rows = this.db
      .prepare(
        `
          SELECT * FROM incidents
          ORDER BY datetime(started_at) DESC
          LIMIT ?
        `
      )
      .all(limit);

    return rows.map((row) => ({
      id: row.id,
      monitorId: row.monitor_id,
      monitorName: row.monitor_name,
      startedAt: row.started_at,
      endedAt: row.ended_at,
      durationSeconds: row.duration_seconds,
      downReason: row.down_reason,
      recoveryReason: row.recovery_reason,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));
  }

  addIncident({ monitorId, monitorName, startedAt, downReason }) {
    const incident = {
      id: crypto.randomUUID(),
      monitorId,
      monitorName,
      startedAt,
      endedAt: null,
      durationSeconds: null,
      downReason,
      recoveryReason: null,
      createdAt: nowIso(),
      updatedAt: nowIso()
    };

    this.db
      .prepare(
        `
          INSERT INTO incidents (
            id, monitor_id, monitor_name, started_at, ended_at,
            duration_seconds, down_reason, recovery_reason,
            created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `
      )
      .run(
        incident.id,
        incident.monitorId,
        incident.monitorName,
        incident.startedAt,
        incident.endedAt,
        incident.durationSeconds,
        incident.downReason,
        incident.recoveryReason,
        incident.createdAt,
        incident.updatedAt
      );

    return incident;
  }

  getOpenIncidentByMonitorId(monitorId) {
    const row = this.db
      .prepare(
        `
          SELECT * FROM incidents
          WHERE monitor_id = ? AND ended_at IS NULL
          ORDER BY datetime(started_at) DESC
          LIMIT 1
        `
      )
      .get(monitorId);

    if (!row) {
      return null;
    }

    return {
      id: row.id,
      monitorId: row.monitor_id,
      monitorName: row.monitor_name,
      startedAt: row.started_at,
      endedAt: row.ended_at,
      durationSeconds: row.duration_seconds,
      downReason: row.down_reason,
      recoveryReason: row.recovery_reason,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  closeIncident(incidentId, { endedAt, recoveryReason }) {
    const incident = this.db.prepare('SELECT * FROM incidents WHERE id = ?').get(incidentId);
    if (!incident) {
      return null;
    }

    if (incident.ended_at) {
      return {
        id: incident.id,
        monitorId: incident.monitor_id,
        monitorName: incident.monitor_name,
        startedAt: incident.started_at,
        endedAt: incident.ended_at,
        durationSeconds: incident.duration_seconds,
        downReason: incident.down_reason,
        recoveryReason: incident.recovery_reason,
        createdAt: incident.created_at,
        updatedAt: incident.updated_at
      };
    }

    const startedMs = new Date(incident.started_at).getTime();
    const endedMs = new Date(endedAt).getTime();
    const durationSeconds =
      Number.isFinite(startedMs) && Number.isFinite(endedMs) && endedMs >= startedMs
        ? Math.round((endedMs - startedMs) / 1000)
        : null;

    const updatedAt = nowIso();

    this.db
      .prepare(
        `
          UPDATE incidents
          SET ended_at = ?, recovery_reason = ?, duration_seconds = ?, updated_at = ?
          WHERE id = ?
        `
      )
      .run(endedAt, recoveryReason, durationSeconds, updatedAt, incidentId);

    return {
      id: incident.id,
      monitorId: incident.monitor_id,
      monitorName: incident.monitor_name,
      startedAt: incident.started_at,
      endedAt,
      durationSeconds,
      downReason: incident.down_reason,
      recoveryReason,
      createdAt: incident.created_at,
      updatedAt
    };
  }

  closeOpenIncidentForMonitor(monitorId, details) {
    const incident = this.getOpenIncidentByMonitorId(monitorId);
    if (!incident) {
      return null;
    }

    return this.closeIncident(incident.id, details);
  }

  addEvent({ monitorId = null, monitorName = null, eventType, message, details = null }) {
    const event = {
      id: crypto.randomUUID(),
      monitorId,
      monitorName,
      eventType,
      message,
      details,
      createdAt: nowIso()
    };

    this.db
      .prepare(
        `
          INSERT INTO events (id, monitor_id, monitor_name, event_type, message, details_json, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `
      )
      .run(
        event.id,
        event.monitorId,
        event.monitorName,
        event.eventType,
        event.message,
        event.details ? JSON.stringify(event.details) : null,
        event.createdAt
      );

    return event;
  }

  listEvents(limit = 200) {
    const rows = this.db
      .prepare(
        `
          SELECT id, monitor_id, monitor_name, event_type, message, details_json, created_at
          FROM events
          ORDER BY datetime(created_at) DESC
          LIMIT ?
        `
      )
      .all(limit);

    return rows.map((row) => ({
      id: row.id,
      monitorId: row.monitor_id,
      monitorName: row.monitor_name,
      eventType: row.event_type,
      message: row.message,
      details: row.details_json ? JSON.parse(row.details_json) : null,
      createdAt: row.created_at
    }));
  }

  pruneOldHistory() {
    const cutoffMs = Date.now() - this.retentionDays * 24 * 60 * 60 * 1000;
    const cutoffIso = new Date(cutoffMs).toISOString();

    const deletedIncidents = this.db
      .prepare('DELETE FROM incidents WHERE ended_at IS NOT NULL AND datetime(ended_at) < datetime(?)')
      .run(cutoffIso).changes;

    const deletedEvents = this.db
      .prepare('DELETE FROM events WHERE datetime(created_at) < datetime(?)')
      .run(cutoffIso).changes;

    return {
      deletedIncidents,
      deletedEvents,
      cutoffIso
    };
  }

  close() {
    this.db.close();
  }
}

module.exports = {
  DataStore
};
