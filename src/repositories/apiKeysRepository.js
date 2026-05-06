const crypto = require('crypto');
const { hashApiKeySecret, nowIso } = require('./shared');

function createApiKeysRepository(db, usersRepository) {
  function findUserById(id) {
    return usersRepository.findUserById(id);
  }

  return {
    createApiKey: ({ userId, name = 'default' }) => {
      const trimmedUserId = String(userId || '').trim();
      if (!trimmedUserId) {
        throw new Error('User id is required.');
      }

      const user = findUserById(trimmedUserId);
      if (!user) {
        throw new Error('User not found.');
      }

      const now = nowIso();
      const keyId = crypto.randomUUID();
      const secret = crypto.randomBytes(32).toString('hex');
      const salt = crypto.randomBytes(16).toString('base64');
      const keyHash = hashApiKeySecret(secret, salt);
      const token = `argus_${keyId}.${secret}`;

      db
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
    },
    authenticateApiKey: (token) => {
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

      const row = db
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

      const computedHash = hashApiKeySecret(secret, row.salt);
      const actualHash = String(row.key_hash || '');
      const computedBuffer = Buffer.from(computedHash);
      const actualBuffer = Buffer.from(actualHash);
      if (computedBuffer.length !== actualBuffer.length || !crypto.timingSafeEqual(computedBuffer, actualBuffer)) {
        return null;
      }

      const now = nowIso();
      db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(now, row.id);

      return {
        id: row.id,
        userId: row.user_id,
        name: row.name,
        createdAt: row.created_at,
        lastUsedAt: now
      };
    }
  };
}

module.exports = {
  createApiKeysRepository
};
