const fs = require('node:fs');
const path = require('node:path');

const config = require('../src/config');
const { DataStore } = require('../src/store');

const inputFile = process.argv[2] || process.env.SEED_MONITORS_FILE || './local/seed-monitors.json';

function resolveInput(filePath) {
  if (path.isAbsolute(filePath)) {
    return filePath;
  }

  return path.resolve(process.cwd(), filePath);
}

function readDefinitions(filePath) {
  const resolved = resolveInput(filePath);

  if (!fs.existsSync(resolved)) {
    throw new Error(
      `Seed monitors file not found: ${resolved}\n` +
        'Create it locally (ignored by git), e.g. ./local/seed-monitors.json'
    );
  }

  const raw = fs.readFileSync(resolved, 'utf8');
  const parsed = JSON.parse(raw);

  if (!Array.isArray(parsed)) {
    throw new Error('Seed monitors file must contain a JSON array.');
  }

  return parsed;
}

function toPayload(definition) {
  return {
    name: String(definition.name || '').trim() || 'Unnamed monitor',
    groupName: String(definition.groupName || 'Default').trim() || 'Default',
    checkType: definition.checkType === 'ping' ? 'ping' : definition.checkType === 'keyword' ? 'keyword' : 'http',
    host: String(definition.host || ''),
    url: String(definition.url || ''),
    keyword: String(definition.keyword || ''),
    keywordCaseSensitive: Boolean(definition.keywordCaseSensitive),
    httpStatusMode: definition.httpStatusMode === '200' ? '200' : '2xx',
    tlsErrorAsFailure: definition.tlsErrorAsFailure !== false,
    webhookType: definition.webhookType === 'discord' ? 'discord' : 'slack',
    webhookUrl: String(definition.webhookUrl || ''),
    timeoutMs: Number(definition.timeoutMs) || config.defaultTimeoutMs,
    active: definition.active !== false
  };
}

function main() {
  const definitions = readDefinitions(inputFile);
  const store = new DataStore(config.dbFile, config.retentionDays);

  try {
    const existingByName = new Map(store.listMonitors().map((monitor) => [monitor.name, monitor]));
    let created = 0;
    let updated = 0;

    for (const definition of definitions) {
      const payload = toPayload(definition);
      const existing = existingByName.get(payload.name);

      if (!existing) {
        store.createMonitor(payload);
        created += 1;
        continue;
      }

      store.updateMonitor(existing.id, payload);
      updated += 1;
    }

    console.log(`Seed complete: created=${created}, updated=${updated}`);
  } finally {
    store.close();
  }
}

try {
  main();
} catch (error) {
  console.error(error.message || error);
  process.exitCode = 1;
}
