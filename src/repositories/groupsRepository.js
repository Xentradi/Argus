const crypto = require('crypto');
const { nowIso, resolveOwnerUserId, rowToGroup } = require('./shared');

function createGroupsRepository(db) {
  return {
    listGroups: (userId = null) => {
      const rows = userId
        ? db
            .prepare(
              `
                SELECT id, user_id, name, webhook_type, webhook_url, created_at, updated_at
                FROM monitor_groups
                WHERE user_id = ?
                ORDER BY lower(name) ASC
              `
            )
            .all(userId)
        : db
            .prepare(
              `
                SELECT id, user_id, name, webhook_type, webhook_url, created_at, updated_at
                FROM monitor_groups
                ORDER BY lower(name) ASC
              `
            )
            .all();

      return rows.map((row) => rowToGroup(row));
    },
    getGroupById: (id, userId = null) => {
      const row = userId
        ? db
            .prepare(
              'SELECT id, user_id, name, webhook_type, webhook_url, created_at, updated_at FROM monitor_groups WHERE id = ? AND user_id = ?'
            )
            .get(id, userId)
        : db
            .prepare('SELECT id, user_id, name, webhook_type, webhook_url, created_at, updated_at FROM monitor_groups WHERE id = ?')
            .get(id);
      return row ? rowToGroup(row) : null;
    },
    createGroup: ({ userId, name, webhookType, webhookUrl }) => {
      const trimmedUserId = resolveOwnerUserId(db, userId);
      const trimmedName = String(name || '').trim();
      if (!trimmedName) {
        throw new Error('Group name is required.');
      }

      const existing = trimmedUserId
        ? db
            .prepare('SELECT id FROM monitor_groups WHERE lower(name) = lower(?) AND user_id = ? LIMIT 1')
            .get(trimmedName, trimmedUserId)
        : db
            .prepare('SELECT id FROM monitor_groups WHERE lower(name) = lower(?) LIMIT 1')
            .get(trimmedName);
      if (existing) {
        throw new Error('Group name already exists.');
      }

      const now = nowIso();
      const group = {
        id: crypto.randomUUID(),
        userId: trimmedUserId,
        name: trimmedName,
        webhookType: webhookType === 'discord' ? 'discord' : 'slack',
        webhookUrl: String(webhookUrl || '').trim(),
        createdAt: now,
        updatedAt: now
      };

      db
        .prepare(
          `
            INSERT INTO monitor_groups (id, user_id, name, webhook_type, webhook_url, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `
        )
        .run(group.id, group.userId, group.name, group.webhookType, group.webhookUrl, group.createdAt, group.updatedAt);

      return group;
    },
    updateGroup: (id, patch, userId = null) => {
      const current = userId
        ? db
            .prepare('SELECT id, user_id, name, webhook_type, webhook_url, created_at, updated_at FROM monitor_groups WHERE id = ? AND user_id = ?')
            .get(id, userId)
        : db
            .prepare('SELECT id, user_id, name, webhook_type, webhook_url, created_at, updated_at FROM monitor_groups WHERE id = ?')
            .get(id);
      if (!current) {
        return null;
      }

      const next = {
        ...rowToGroup(current),
        ...patch,
        name: String(patch.name !== undefined ? patch.name : current.name).trim(),
        webhookType: patch.webhookType === 'discord' ? 'discord' : patch.webhookType === 'slack' ? 'slack' : current.webhook_type,
        webhookUrl: String(patch.webhookUrl !== undefined ? patch.webhookUrl : current.webhook_url).trim(),
        updatedAt: nowIso()
      };

      if (!next.name) {
        throw new Error('Group name is required.');
      }

      const nameConflict = current.user_id
        ? db
            .prepare('SELECT id FROM monitor_groups WHERE lower(name) = lower(?) AND id != ? AND user_id = ? LIMIT 1')
            .get(next.name, id, current.user_id)
        : db
            .prepare('SELECT id FROM monitor_groups WHERE lower(name) = lower(?) AND id != ? LIMIT 1')
            .get(next.name, id);
      if (nameConflict) {
        throw new Error('Group name already exists.');
      }

      if (current.user_id) {
        db
          .prepare(
            `
              UPDATE monitor_groups
              SET name = ?, webhook_type = ?, webhook_url = ?, updated_at = ?
              WHERE id = ? AND user_id = ?
            `
          )
          .run(next.name, next.webhookType, next.webhookUrl, next.updatedAt, id, current.user_id);
      } else {
        db
          .prepare(
            `
              UPDATE monitor_groups
              SET name = ?, webhook_type = ?, webhook_url = ?, updated_at = ?
              WHERE id = ?
            `
          )
          .run(next.name, next.webhookType, next.webhookUrl, next.updatedAt, id);
      }

      if (current.user_id) {
        db
          .prepare(
            `
              UPDATE monitors
              SET group_name = ?, webhook_type = ?, webhook_url = ?, updated_at = ?
              WHERE group_id = ? AND user_id = ?
            `
          )
          .run(next.name, next.webhookType, next.webhookUrl, nowIso(), id, current.user_id);
      } else {
        db
          .prepare(
            `
              UPDATE monitors
              SET group_name = ?, webhook_type = ?, webhook_url = ?, updated_at = ?
              WHERE group_id = ?
            `
          )
          .run(next.name, next.webhookType, next.webhookUrl, nowIso(), id);
      }

      return {
        id,
        userId: current.user_id || null,
        name: next.name,
        webhookType: next.webhookType,
        webhookUrl: next.webhookUrl,
        createdAt: current.created_at,
        updatedAt: next.updatedAt
      };
    },
    deleteGroup: (id, userId = null) => {
      const group = userId
        ? db
            .prepare('SELECT id, user_id, name, webhook_type, webhook_url, created_at, updated_at FROM monitor_groups WHERE id = ? AND user_id = ?')
            .get(id, userId)
        : db
            .prepare('SELECT id, user_id, name, webhook_type, webhook_url, created_at, updated_at FROM monitor_groups WHERE id = ?')
            .get(id);
      if (!group) {
        return null;
      }

      const removeGroup = db.transaction(() => {
        if (group.user_id) {
          db
            .prepare(
              `
                UPDATE monitors
                SET group_id = NULL, group_name = '', webhook_type = ?, webhook_url = ?, updated_at = ?
                WHERE group_id = ? AND user_id = ?
              `
            )
            .run(group.webhook_type, group.webhook_url, nowIso(), id, group.user_id);

          db.prepare('DELETE FROM monitor_groups WHERE id = ? AND user_id = ?').run(id, group.user_id);
        } else {
          db
            .prepare(
              `
                UPDATE monitors
                SET group_id = NULL, group_name = '', webhook_type = ?, webhook_url = ?, updated_at = ?
                WHERE group_id = ?
              `
            )
            .run(group.webhook_type, group.webhook_url, nowIso(), id);

          db.prepare('DELETE FROM monitor_groups WHERE id = ?').run(id);
        }
      });

      removeGroup();
      return rowToGroup(group);
    }
  };
}

module.exports = {
  createGroupsRepository
};
