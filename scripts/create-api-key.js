#!/usr/bin/env node

const path = require('path');

const config = require('../src/config');
const { DataStore } = require('../src/store');

function usage() {
  console.error('Usage: node scripts/create-api-key.js <username> [key-name]');
}

async function main() {
  const username = String(process.argv[2] || '').trim();
  const keyName = String(process.argv[3] || 'default').trim() || 'default';

  if (!username) {
    usage();
    process.exit(1);
  }

  const dbFile = path.resolve(config.dbFile);
  const store = new DataStore(dbFile, config.retentionDays);

  try {
    const user = store.findUserByUsername(username);
    if (!user) {
      console.error(`User not found: ${username}`);
      process.exit(1);
    }

    const created = store.createApiKey({
      userId: user.id,
      name: keyName
    });

    console.log('API key created.');
    console.log(`User: ${user.username} (${user.id})`);
    console.log(`Key ID: ${created.id}`);
    console.log(`Name: ${created.name}`);
    console.log(`Created At: ${created.createdAt}`);
    console.log('');
    console.log('Token (store this now; treat as secret):');
    console.log(created.token);
  } finally {
    store.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
