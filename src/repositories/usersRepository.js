const crypto = require('crypto');
const { nowIso } = require('./shared');

function createUsersRepository(db) {
  return {
    hasUsers: () => {
      const row = db.prepare('SELECT COUNT(*) AS count FROM users').get();
      return row.count > 0;
    },
    getMeta: (key) => {
      const row = db.prepare('SELECT value FROM meta WHERE key = ?').get(key);
      return row ? row.value : null;
    },
    setMeta: (key, value) => {
      db
        .prepare(
          `
            INSERT INTO meta(key, value) VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
          `
        )
        .run(key, value);
    },
    getSessionSecret: () => {
      const existing = db.prepare('SELECT value FROM meta WHERE key = ?').get('session_secret');
      if (existing && existing.value) {
        return existing.value;
      }

      const generated = crypto.randomBytes(32).toString('hex');
      db
        .prepare(
          `
            INSERT INTO meta(key, value) VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
          `
        )
        .run('session_secret', generated);
      return generated;
    },
    createUser: ({ username, passwordHash, totpSecret }) => {
      const trimmed = String(username || '').trim();
      if (!trimmed) {
        throw new Error('Username is required.');
      }

      const existing = db
        .prepare('SELECT id FROM users WHERE lower(username) = lower(?)')
        .get(trimmed);
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

      db
        .prepare(
          `
            INSERT INTO users (id, username, password_hash, totp_secret, created_at)
            VALUES (?, ?, ?, ?, ?)
          `
        )
        .run(user.id, user.username, user.passwordHash, user.totpSecret, user.createdAt);

      return user;
    },
    findUserByUsername: (username) => {
      const trimmed = String(username || '').trim();
      if (!trimmed) {
        return null;
      }

      const row = db
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
    },
    findUserById: (id) => {
      const row = db
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
  };
}

module.exports = {
  createUsersRepository
};
