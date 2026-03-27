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

      CREATE TABLE IF NOT EXISTS monitor_groups (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        name TEXT NOT NULL UNIQUE,
        webhook_type TEXT NOT NULL DEFAULT 'slack',
        webhook_url TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS monitors (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        name TEXT NOT NULL,
        group_name TEXT NOT NULL DEFAULT 'Default',
        group_id TEXT,
        sort_order INTEGER NOT NULL DEFAULT 0,
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
        first_success_at TEXT,
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
        user_id TEXT,
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
        user_id TEXT,
        monitor_id TEXT,
        monitor_name TEXT,
        event_type TEXT NOT NULL,
        message TEXT NOT NULL,
        details_json TEXT,
        created_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
      CREATE INDEX IF NOT EXISTS idx_events_monitor ON events(monitor_id);

      CREATE TABLE IF NOT EXISTS status_pages (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        name TEXT NOT NULL,
        slug TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS status_page_monitors (
        status_page_id TEXT NOT NULL,
        monitor_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (status_page_id, monitor_id),
        FOREIGN KEY (status_page_id) REFERENCES status_pages(id) ON DELETE CASCADE,
        FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_status_pages_slug ON status_pages(slug);
      CREATE INDEX IF NOT EXISTS idx_status_page_monitors_page ON status_page_monitors(status_page_id);
      CREATE INDEX IF NOT EXISTS idx_status_page_monitors_monitor ON status_page_monitors(monitor_id);

      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        key_prefix TEXT NOT NULL,
        salt TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        revoked_at TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
      CREATE INDEX IF NOT EXISTS idx_api_keys_revoked ON api_keys(revoked_at);
    `);

    this.migrateIncidentsTableIfNeeded();
    this.migrateMonitorsGroupColumnIfNeeded();
    this.migrateMonitorsGroupIdColumnIfNeeded();
    this.migrateMonitorsSortOrderColumnIfNeeded();
    this.migrateMonitorsFirstSuccessColumnIfNeeded();
    this.migrateOwnershipColumnsIfNeeded();
    this.migrateLegacyGroupsIfNeeded();
    this.ensureMonitorIndexes();
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

  migrateMonitorsGroupIdColumnIfNeeded() {
    const columns = this.db.prepare("PRAGMA table_info('monitors')").all();
    const hasGroupIdColumn = columns.some((column) => column.name === 'group_id');

    if (!hasGroupIdColumn) {
      this.db.prepare('ALTER TABLE monitors ADD COLUMN group_id TEXT').run();
    }
  }

  migrateMonitorsSortOrderColumnIfNeeded() {
    const columns = this.db.prepare("PRAGMA table_info('monitors')").all();
    const hasSortOrderColumn = columns.some((column) => column.name === 'sort_order');

    if (!hasSortOrderColumn) {
      this.db.prepare('ALTER TABLE monitors ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0').run();

      const monitors = this.db
        .prepare(
          `
            SELECT id
            FROM monitors
            ORDER BY datetime(created_at) ASC, name ASC
          `
        )
        .all();

      const updateSortOrder = this.db.prepare('UPDATE monitors SET sort_order = ? WHERE id = ?');
      const migrateSortOrder = this.db.transaction(() => {
        monitors.forEach((monitor, index) => {
          updateSortOrder.run(index + 1, monitor.id);
        });
      });

      migrateSortOrder();
    }
  }

  migrateMonitorsFirstSuccessColumnIfNeeded() {
    const columns = this.db.prepare("PRAGMA table_info('monitors')").all();
    const hasFirstSuccessColumn = columns.some((column) => column.name === 'first_success_at');

    if (!hasFirstSuccessColumn) {
      this.db.prepare('ALTER TABLE monitors ADD COLUMN first_success_at TEXT').run();
    }

    // Best-effort backfill for legacy rows that are currently up.
    this.db
      .prepare(
        `
          UPDATE monitors
          SET first_success_at = created_at
          WHERE first_success_at IS NULL
            AND status = 'up'
            AND last_success_at IS NOT NULL
        `
      )
      .run();
  }

  migrateOwnershipColumnsIfNeeded() {
    const defaultOwnerRow = this.db
      .prepare('SELECT id FROM users ORDER BY datetime(created_at) ASC LIMIT 1')
      .get();
    const defaultOwnerId = defaultOwnerRow ? defaultOwnerRow.id : null;

    const monitorsColumns = this.db.prepare("PRAGMA table_info('monitors')").all();
    if (!monitorsColumns.some((column) => column.name === 'user_id')) {
      this.db.prepare('ALTER TABLE monitors ADD COLUMN user_id TEXT').run();
    }

    const groupsColumns = this.db.prepare("PRAGMA table_info('monitor_groups')").all();
    if (!groupsColumns.some((column) => column.name === 'user_id')) {
      this.db.prepare('ALTER TABLE monitor_groups ADD COLUMN user_id TEXT').run();
    }

    const statusPageColumns = this.db.prepare("PRAGMA table_info('status_pages')").all();
    if (!statusPageColumns.some((column) => column.name === 'user_id')) {
      this.db.prepare('ALTER TABLE status_pages ADD COLUMN user_id TEXT').run();
    }

    const incidentColumns = this.db.prepare("PRAGMA table_info('incidents')").all();
    if (!incidentColumns.some((column) => column.name === 'user_id')) {
      this.db.prepare('ALTER TABLE incidents ADD COLUMN user_id TEXT').run();
    }

    const eventColumns = this.db.prepare("PRAGMA table_info('events')").all();
    if (!eventColumns.some((column) => column.name === 'user_id')) {
      this.db.prepare('ALTER TABLE events ADD COLUMN user_id TEXT').run();
    }

    if (!defaultOwnerId) {
      return;
    }

    this.db.prepare('UPDATE monitors SET user_id = ? WHERE user_id IS NULL').run(defaultOwnerId);
    this.db.prepare('UPDATE monitor_groups SET user_id = ? WHERE user_id IS NULL').run(defaultOwnerId);
    this.db.prepare('UPDATE status_pages SET user_id = ? WHERE user_id IS NULL').run(defaultOwnerId);

    this.db
      .prepare(
        `
          UPDATE incidents
          SET user_id = (
            SELECT monitors.user_id
            FROM monitors
            WHERE monitors.id = incidents.monitor_id
          )
          WHERE user_id IS NULL
        `
      )
      .run();
    this.db.prepare('UPDATE incidents SET user_id = ? WHERE user_id IS NULL').run(defaultOwnerId);

    this.db
      .prepare(
        `
          UPDATE events
          SET user_id = (
            SELECT monitors.user_id
            FROM monitors
            WHERE monitors.id = events.monitor_id
          )
          WHERE user_id IS NULL
        `
      )
      .run();
    this.db.prepare('UPDATE events SET user_id = ? WHERE user_id IS NULL').run(defaultOwnerId);
  }

  migrateLegacyGroupsIfNeeded() {
    const legacyGroupNames = this.db
      .prepare(
        `
          SELECT DISTINCT group_name
          FROM monitors
          WHERE group_id IS NULL
            AND trim(group_name) != ''
            AND lower(trim(group_name)) != 'ungrouped'
        `
      )
      .all()
      .map((row) => row.group_name);

    if (legacyGroupNames.length === 0) {
      return;
    }

    const migrateLegacyGroup = this.db.transaction((groupName) => {
      const monitors = this.db
        .prepare(
          `
            SELECT id, webhook_type, webhook_url
            FROM monitors
            WHERE group_id IS NULL AND group_name = ?
          `
        )
        .all(groupName);

      if (monitors.length === 0) {
        return;
      }

      const baseline = monitors[0];
      const hasUniformWebhook = monitors.every(
        (monitor) => monitor.webhook_type === baseline.webhook_type && monitor.webhook_url === baseline.webhook_url
      );

      if (!hasUniformWebhook) {
        return;
      }

      const existingGroup = this.db
        .prepare('SELECT id FROM monitor_groups WHERE lower(name) = lower(?) LIMIT 1')
        .get(groupName);
      const groupId = existingGroup ? existingGroup.id : crypto.randomUUID();
      const now = nowIso();

      if (!existingGroup) {
        this.db
          .prepare(
            `
              INSERT INTO monitor_groups (id, name, webhook_type, webhook_url, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, ?)
            `
          )
          .run(groupId, groupName, baseline.webhook_type, baseline.webhook_url, now, now);
      }

      this.db
        .prepare(
          `
            UPDATE monitors
            SET group_id = ?, group_name = ?, sort_order = CASE WHEN sort_order <= 0 THEN rowid ELSE sort_order END
            WHERE group_id IS NULL AND group_name = ?
          `
        )
        .run(groupId, groupName, groupName);
    });

    for (const groupName of legacyGroupNames) {
      migrateLegacyGroup(groupName);
    }
  }

  ensureMonitorIndexes() {
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_monitors_group_order ON monitors(group_id, sort_order, created_at)');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_monitors_user ON monitors(user_id)');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_groups_user ON monitor_groups(user_id)');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_incidents_user ON incidents(user_id)');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id)');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_status_pages_user ON status_pages(user_id)');
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

  resolveOwnerUserId(candidateUserId) {
    const trimmed = String(candidateUserId || '').trim();
    if (trimmed) {
      return trimmed;
    }

    const row = this.db.prepare('SELECT id FROM users ORDER BY datetime(created_at) ASC LIMIT 1').get();
    return row ? row.id : null;
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

  hashApiKeySecret(secret, saltBase64) {
    const salt = Buffer.from(String(saltBase64 || ''), 'base64');
    return crypto.pbkdf2Sync(String(secret || ''), salt, 120000, 32, 'sha256').toString('base64');
  }

  createApiKey({ userId, name = 'default' }) {
    const trimmedUserId = String(userId || '').trim();
    if (!trimmedUserId) {
      throw new Error('User id is required.');
    }

    const user = this.findUserById(trimmedUserId);
    if (!user) {
      throw new Error('User not found.');
    }

    const now = nowIso();
    const keyId = crypto.randomUUID();
    const secret = crypto.randomBytes(32).toString('hex');
    const salt = crypto.randomBytes(16).toString('base64');
    const keyHash = this.hashApiKeySecret(secret, salt);
    const token = `argus_${keyId}.${secret}`;

    this.db
      .prepare(
        `
          INSERT INTO api_keys (id, user_id, name, key_prefix, salt, key_hash, created_at, last_used_at, revoked_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)
        `
      )
      .run(keyId, trimmedUserId, String(name || 'default').trim() || 'default', token.slice(0, 16), salt, keyHash, now);

    return {
      id: keyId,
      userId: trimmedUserId,
      name: String(name || 'default').trim() || 'default',
      token,
      createdAt: now
    };
  }

  authenticateApiKey(token) {
    const value = String(token || '').trim();
    if (!value.startsWith('argus_')) {
      return null;
    }

    const dotIndex = value.indexOf('.');
    if (dotIndex < 0) {
      return null;
    }

    const keyId = value.slice('argus_'.length, dotIndex);
    const secret = value.slice(dotIndex + 1);
    if (!keyId || !secret) {
      return null;
    }

    const row = this.db
      .prepare(
        `
          SELECT id, user_id, name, salt, key_hash, created_at, last_used_at
          FROM api_keys
          WHERE id = ? AND revoked_at IS NULL
          LIMIT 1
        `
      )
      .get(keyId);
    if (!row) {
      return null;
    }

    const computedHash = this.hashApiKeySecret(secret, row.salt);
    const actualHash = String(row.key_hash || '');
    const computedBuffer = Buffer.from(computedHash);
    const actualBuffer = Buffer.from(actualHash);
    if (computedBuffer.length !== actualBuffer.length || !crypto.timingSafeEqual(computedBuffer, actualBuffer)) {
      return null;
    }

    const now = nowIso();
    this.db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(now, row.id);

    return {
      id: row.id,
      userId: row.user_id,
      name: row.name,
      createdAt: row.created_at,
      lastUsedAt: now
    };
  }

  rowToGroup(row) {
    return {
      id: row.id,
      userId: row.user_id || null,
      name: row.name,
      webhookType: row.webhook_type,
      webhookUrl: row.webhook_url,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  rowToStatusPage(row) {
    return {
      id: row.id,
      userId: row.user_id || null,
      name: row.name,
      slug: row.slug,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  listGroups(userId = null) {
    const rows = userId
      ? this.db
          .prepare(
            `
              SELECT id, user_id, name, webhook_type, webhook_url, created_at, updated_at
              FROM monitor_groups
              WHERE user_id = ?
              ORDER BY lower(name) ASC
            `
          )
          .all(userId)
      : this.db
          .prepare(
            `
              SELECT id, user_id, name, webhook_type, webhook_url, created_at, updated_at
              FROM monitor_groups
              ORDER BY lower(name) ASC
            `
          )
          .all();

    return rows.map((row) => this.rowToGroup(row));
  }

  getGroupById(id, userId = null) {
    const row = userId
      ? this.db
          .prepare(
            'SELECT id, user_id, name, webhook_type, webhook_url, created_at, updated_at FROM monitor_groups WHERE id = ? AND user_id = ?'
          )
          .get(id, userId)
      : this.db
          .prepare('SELECT id, user_id, name, webhook_type, webhook_url, created_at, updated_at FROM monitor_groups WHERE id = ?')
          .get(id);
    return row ? this.rowToGroup(row) : null;
  }

  listStatusPages(userId = null) {
    const rows = userId
      ? this.db
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
      : this.db
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
      ...this.rowToStatusPage(row),
      monitorCount: Number(row.monitor_count || 0)
    }));
  }

  listMonitorsForStatusPage(statusPageId) {
    const rows = this.db
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

    return rows.map((row) => this.rowToMonitor(row));
  }

  getStatusPageById(id, userId = null) {
    const row = userId
      ? this.db
          .prepare('SELECT id, user_id, name, slug, created_at, updated_at FROM status_pages WHERE id = ? AND user_id = ?')
          .get(id, userId)
      : this.db
          .prepare('SELECT id, user_id, name, slug, created_at, updated_at FROM status_pages WHERE id = ?')
          .get(id);
    if (!row) {
      return null;
    }

    const page = this.rowToStatusPage(row);
    const monitors = this.listMonitorsForStatusPage(page.id);

    return {
      ...page,
      monitors,
      monitorCount: monitors.length
    };
  }

  getStatusPageBySlug(slug, userId = null) {
    const normalizedSlug = String(slug || '').trim().toLowerCase();
    if (!normalizedSlug) {
      return null;
    }

    const row = userId
      ? this.db
          .prepare(
            'SELECT id, user_id, name, slug, created_at, updated_at FROM status_pages WHERE lower(slug) = lower(?) AND user_id = ? LIMIT 1'
          )
          .get(normalizedSlug, userId)
      : this.db
          .prepare('SELECT id, user_id, name, slug, created_at, updated_at FROM status_pages WHERE lower(slug) = lower(?) LIMIT 1')
          .get(normalizedSlug);

    if (!row) {
      return null;
    }

    return this.getStatusPageById(row.id, userId);
  }

  createStatusPage({ userId, name, slug, monitorIds }) {
    const trimmedUserId = this.resolveOwnerUserId(userId);

    const trimmedName = String(name || '').trim();
    const normalizedSlug = String(slug || '')
      .trim()
      .toLowerCase();

    if (!trimmedName) {
      throw new Error('Status page name is required.');
    }

    if (!normalizedSlug) {
      throw new Error('Status page slug is required.');
    }

    const slugConflict = this.db
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
      ? this.db
          .prepare(`SELECT id FROM monitors WHERE user_id = ? AND id IN (${placeholders})`)
          .all(trimmedUserId, ...requestedMonitorIds)
      : this.db
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

    const create = this.db.transaction(() => {
      this.db
        .prepare(
          `
            INSERT INTO status_pages (id, user_id, name, slug, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
          `
        )
        .run(statusPage.id, statusPage.userId, statusPage.name, statusPage.slug, statusPage.createdAt, statusPage.updatedAt);

      const insertMonitor = this.db.prepare(
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

    return this.getStatusPageById(statusPage.id, trimmedUserId);
  }

  deleteStatusPage(id, userId = null) {
    const existing = this.getStatusPageById(id, userId);
    if (!existing) {
      return null;
    }

    if (existing.userId) {
      this.db.prepare('DELETE FROM status_pages WHERE id = ? AND user_id = ?').run(id, existing.userId);
    } else {
      this.db.prepare('DELETE FROM status_pages WHERE id = ?').run(id);
    }
    return existing;
  }

  createGroup({ userId, name, webhookType, webhookUrl }) {
    const trimmedUserId = this.resolveOwnerUserId(userId);

    const trimmedName = String(name || '').trim();
    if (!trimmedName) {
      throw new Error('Group name is required.');
    }

    const existing = trimmedUserId
      ? this.db
          .prepare('SELECT id FROM monitor_groups WHERE lower(name) = lower(?) AND user_id = ? LIMIT 1')
          .get(trimmedName, trimmedUserId)
      : this.db
          .prepare('SELECT id FROM monitor_groups WHERE lower(name) = lower(?) LIMIT 1')
          .get(trimmedName);
    if (existing) {
      throw new Error('Group name already exists.');
    }

    const group = {
      id: crypto.randomUUID(),
      userId: trimmedUserId,
      name: trimmedName,
      webhookType: webhookType === 'discord' ? 'discord' : 'slack',
      webhookUrl: String(webhookUrl || '').trim(),
      createdAt: nowIso(),
      updatedAt: nowIso()
    };

    this.db
      .prepare(
        `
          INSERT INTO monitor_groups (id, user_id, name, webhook_type, webhook_url, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `
      )
      .run(group.id, group.userId, group.name, group.webhookType, group.webhookUrl, group.createdAt, group.updatedAt);

    return group;
  }

  updateGroup(id, patch, userId = null) {
    const current = this.getGroupById(id, userId);
    if (!current) {
      return null;
    }

    const next = {
      ...current,
      ...patch,
      name: String(patch.name !== undefined ? patch.name : current.name).trim(),
      webhookType: patch.webhookType === 'discord' ? 'discord' : patch.webhookType === 'slack' ? 'slack' : current.webhookType,
      webhookUrl: String(patch.webhookUrl !== undefined ? patch.webhookUrl : current.webhookUrl).trim(),
      updatedAt: nowIso()
    };

    if (!next.name) {
      throw new Error('Group name is required.');
    }

    const nameConflict = current.userId
      ? this.db
          .prepare('SELECT id FROM monitor_groups WHERE lower(name) = lower(?) AND id != ? AND user_id = ? LIMIT 1')
          .get(next.name, id, current.userId)
      : this.db
          .prepare('SELECT id FROM monitor_groups WHERE lower(name) = lower(?) AND id != ? LIMIT 1')
          .get(next.name, id);
    if (nameConflict) {
      throw new Error('Group name already exists.');
    }

    if (current.userId) {
      this.db
        .prepare(
          `
            UPDATE monitor_groups
            SET name = ?, webhook_type = ?, webhook_url = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
          `
        )
        .run(next.name, next.webhookType, next.webhookUrl, next.updatedAt, id, current.userId);
    } else {
      this.db
        .prepare(
          `
            UPDATE monitor_groups
            SET name = ?, webhook_type = ?, webhook_url = ?, updated_at = ?
            WHERE id = ?
          `
        )
        .run(next.name, next.webhookType, next.webhookUrl, next.updatedAt, id);
    }

    if (current.userId) {
      this.db
        .prepare(
          `
            UPDATE monitors
            SET group_name = ?, webhook_type = ?, webhook_url = ?, updated_at = ?
            WHERE group_id = ? AND user_id = ?
          `
        )
        .run(next.name, next.webhookType, next.webhookUrl, nowIso(), id, current.userId);
    } else {
      this.db
        .prepare(
          `
            UPDATE monitors
            SET group_name = ?, webhook_type = ?, webhook_url = ?, updated_at = ?
            WHERE group_id = ?
          `
        )
        .run(next.name, next.webhookType, next.webhookUrl, nowIso(), id);
    }

    return this.getGroupById(id, current.userId);
  }

  deleteGroup(id, userId = null) {
    const group = this.getGroupById(id, userId);
    if (!group) {
      return null;
    }

    const removeGroup = this.db.transaction(() => {
      if (group.userId) {
        this.db
          .prepare(
            `
              UPDATE monitors
              SET group_id = NULL, group_name = '', webhook_type = ?, webhook_url = ?, updated_at = ?
              WHERE group_id = ? AND user_id = ?
            `
          )
          .run(group.webhookType, group.webhookUrl, nowIso(), id, group.userId);

        this.db.prepare('DELETE FROM monitor_groups WHERE id = ? AND user_id = ?').run(id, group.userId);
      } else {
        this.db
          .prepare(
            `
              UPDATE monitors
              SET group_id = NULL, group_name = '', webhook_type = ?, webhook_url = ?, updated_at = ?
              WHERE group_id = ?
            `
          )
          .run(group.webhookType, group.webhookUrl, nowIso(), id);

        this.db.prepare('DELETE FROM monitor_groups WHERE id = ?').run(id);
      }
    });

    removeGroup();
    return group;
  }

  rowToMonitor(row) {
    return {
      id: row.id,
      userId: row.user_id || null,
      name: row.name,
      groupId: row.group_id || null,
      groupName: row.group_name || '',
      sortOrder: Number.isFinite(Number(row.sort_order)) ? Number(row.sort_order) : 0,
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
        firstSuccessAt: row.first_success_at,
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

  listMonitors(userId = null) {
    const rows = userId
      ? this.db
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
      : this.db
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

    return rows.map((row) => this.rowToMonitor(row));
  }

  getMonitorById(id, userId = null) {
    const row = userId
      ? this.db.prepare('SELECT * FROM monitors WHERE id = ? AND user_id = ?').get(id, userId)
      : this.db.prepare('SELECT * FROM monitors WHERE id = ?').get(id);
    return row ? this.rowToMonitor(row) : null;
  }

  getNextMonitorSortOrder(groupId, userId = null) {
    if (groupId) {
      const row = userId
        ? this.db
            .prepare('SELECT COALESCE(MAX(sort_order), 0) AS max_sort_order FROM monitors WHERE group_id = ? AND user_id = ?')
            .get(groupId, userId)
        : this.db
            .prepare('SELECT COALESCE(MAX(sort_order), 0) AS max_sort_order FROM monitors WHERE group_id = ?')
            .get(groupId);
      return Number(row.max_sort_order || 0) + 1;
    }

    const row = userId
      ? this.db
          .prepare('SELECT COALESCE(MAX(sort_order), 0) AS max_sort_order FROM monitors WHERE group_id IS NULL AND user_id = ?')
          .get(userId)
      : this.db
          .prepare('SELECT COALESCE(MAX(sort_order), 0) AS max_sort_order FROM monitors WHERE group_id IS NULL')
          .get();
    return Number(row.max_sort_order || 0) + 1;
  }

  createMonitor(payload) {
    const now = nowIso();
    const groupId = payload.groupId || null;
    const userId = this.resolveOwnerUserId(payload.userId);

    const monitor = {
      id: crypto.randomUUID(),
      userId,
      name: payload.name || 'Unnamed monitor',
      groupId,
      groupName: String(payload.groupName || '').trim(),
      sortOrder: Number.isFinite(Number(payload.sortOrder))
        ? Number(payload.sortOrder)
        : this.getNextMonitorSortOrder(groupId, userId),
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
        firstSuccessAt: null,
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
            id, user_id, name, group_name, group_id, sort_order, check_type, host, url, keyword,
            keyword_case_sensitive, http_status_mode, tls_error_as_failure,
            webhook_type, webhook_url, timeout_ms, active,
            created_at, updated_at,
            status, last_check_at, first_success_at, last_success_at, last_failure_at,
            last_error, last_response_ms, last_http_status,
            last_keyword_matched, last_tls_error, next_check_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        monitor.runtime.nextCheckAt
      );

    return monitor;
  }

  updateMonitor(id, patch, userId = null) {
    const current = this.getMonitorById(id, userId);
    if (!current) {
      return null;
    }

    const targetGroupId = patch.groupId !== undefined ? patch.groupId || null : current.groupId;
    const groupChanged = targetGroupId !== current.groupId;
    const sortOrder =
      patch.sortOrder !== undefined
        ? Number(patch.sortOrder)
        : groupChanged
          ? this.getNextMonitorSortOrder(targetGroupId, current.userId)
          : current.sortOrder;

    const next = {
      ...current,
      ...patch,
      groupId: targetGroupId,
      groupName: String(patch.groupName !== undefined ? patch.groupName : current.groupName).trim(),
      sortOrder: Number.isFinite(sortOrder) ? sortOrder : current.sortOrder,
      runtime: {
        ...current.runtime,
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
      next.runtime.nextCheckAt,
      id
    ];

    if (current.userId) {
      this.db
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
              next_check_at = ?
            WHERE id = ? AND user_id = ?
          `
        )
        .run(...updateValues, current.userId);
    } else {
      this.db
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
              next_check_at = ?
            WHERE id = ?
          `
        )
        .run(...updateValues);
    }

    return this.getMonitorById(id, current.userId);
  }

  updateMonitorRuntime(id, runtimePatch) {
    return this.updateMonitor(id, {
      runtime: runtimePatch
    });
  }

  deleteMonitor(id, userId = null) {
    const existing = this.getMonitorById(id, userId);
    if (!existing) {
      return null;
    }

    if (existing.userId) {
      this.db.prepare('DELETE FROM monitors WHERE id = ? AND user_id = ?').run(id, existing.userId);
    } else {
      this.db.prepare('DELETE FROM monitors WHERE id = ?').run(id);
    }
    return existing;
  }

  moveMonitorInGroup(id, direction, userId = null) {
    const monitor = this.getMonitorById(id, userId);
    if (!monitor) {
      return null;
    }

    const rows = monitor.groupId
      ? monitor.userId
        ? this.db
            .prepare(
              `
                SELECT id, sort_order, created_at, name
                FROM monitors
                WHERE group_id = ? AND user_id = ?
                ORDER BY sort_order ASC, datetime(created_at) ASC, lower(name) ASC
              `
            )
            .all(monitor.groupId, monitor.userId)
        : this.db
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
        ? this.db
            .prepare(
              `
                SELECT id, sort_order, created_at, name
                FROM monitors
                WHERE group_id IS NULL AND user_id = ?
                ORDER BY sort_order ASC, datetime(created_at) ASC, lower(name) ASC
              `
            )
            .all(monitor.userId)
        : this.db
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

    const normalize = this.db.transaction(() => {
      const update = this.db.prepare('UPDATE monitors SET sort_order = ?, updated_at = ? WHERE id = ?');
      rows.forEach((row, index) => {
        update.run(index + 1, nowIso(), row.id);
      });
    });
    normalize();

    const normalizedRows = monitor.groupId
      ? monitor.userId
        ? this.db
            .prepare(
              `
                SELECT id, sort_order
                FROM monitors
                WHERE group_id = ? AND user_id = ?
                ORDER BY sort_order ASC
              `
            )
            .all(monitor.groupId, monitor.userId)
        : this.db
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
        ? this.db
            .prepare(
              `
                SELECT id, sort_order
                FROM monitors
                WHERE group_id IS NULL AND user_id = ?
                ORDER BY sort_order ASC
              `
            )
            .all(monitor.userId)
        : this.db
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
      return this.getMonitorById(id, monitor.userId);
    }

    const targetIndex = direction === 'up' ? currentIndex - 1 : currentIndex + 1;
    if (targetIndex < 0 || targetIndex >= normalizedRows.length) {
      return this.getMonitorById(id, monitor.userId);
    }

    const currentRow = normalizedRows[currentIndex];
    const targetRow = normalizedRows[targetIndex];

    const swap = this.db.transaction(() => {
      const now = nowIso();
      const update = this.db.prepare('UPDATE monitors SET sort_order = ?, updated_at = ? WHERE id = ?');
      update.run(targetRow.sort_order, now, currentRow.id);
      update.run(currentRow.sort_order, now, targetRow.id);
    });

    swap();
    return this.getMonitorById(id, monitor.userId);
  }

  listIncidents(limit = 100, userId = null) {
    const rows = userId
      ? this.db
          .prepare(
            `
              SELECT * FROM incidents
              WHERE user_id = ?
              ORDER BY datetime(started_at) DESC
              LIMIT ?
            `
          )
          .all(userId, limit)
      : this.db
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
      userId: row.user_id || null,
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

  listOpenIncidents(userId = null) {
    const rows = userId
      ? this.db
          .prepare(
            `
              SELECT * FROM incidents
              WHERE ended_at IS NULL AND user_id = ?
              ORDER BY datetime(started_at) DESC
            `
          )
          .all(userId)
      : this.db
          .prepare(
            `
              SELECT * FROM incidents
              WHERE ended_at IS NULL
              ORDER BY datetime(started_at) DESC
            `
          )
          .all();

    return rows.map((row) => ({
      id: row.id,
      userId: row.user_id || null,
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

  addIncident({ userId = null, monitorId, monitorName, startedAt, downReason }) {
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
      createdAt: nowIso(),
      updatedAt: nowIso()
    };

    this.db
      .prepare(
        `
          INSERT INTO incidents (
            id, user_id, monitor_id, monitor_name, started_at, ended_at,
            duration_seconds, down_reason, recovery_reason,
            created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
      userId: row.user_id || null,
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
        userId: incident.user_id || null,
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
      userId: incident.user_id || null,
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

  getLatestRecoveryTimesByMonitorIds(monitorIds) {
    const ids = Array.from(new Set((Array.isArray(monitorIds) ? monitorIds : []).map((id) => String(id || '').trim()).filter(Boolean)));
    if (ids.length === 0) {
      return {};
    }

    const placeholders = ids.map(() => '?').join(', ');
    const rows = this.db
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

  calculateMonitorUptimeStats(monitorId, at = nowIso(), userId = null) {
    const monitor = this.getMonitorById(monitorId, userId);
    if (!monitor) {
      return null;
    }

    const endMsRaw = new Date(at).getTime();
    const endMs = Number.isFinite(endMsRaw) ? endMsRaw : Date.now();

    const startMsRaw = new Date(monitor.createdAt).getTime();
    const startMs = Number.isFinite(startMsRaw) ? Math.min(startMsRaw, endMs) : endMs;

    const startIso = new Date(startMs).toISOString();
    const endIso = new Date(endMs).toISOString();

    const incidentRows = this.db
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

  addEvent({ userId = null, monitorId = null, monitorName = null, eventType, message, details = null }) {
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

    this.db
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
  }

  countEvents(userId = null) {
    const row = userId
      ? this.db.prepare('SELECT COUNT(*) AS count FROM events WHERE user_id = ?').get(userId)
      : this.db.prepare('SELECT COUNT(*) AS count FROM events').get();
    return Number(row.count || 0);
  }

  listEvents(limit = 200, offset = 0, userId = null) {
    const rows = userId
      ? this.db
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
      : this.db
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

    return rows.map((row) => ({
      id: row.id,
      userId: row.user_id || null,
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
