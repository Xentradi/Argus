const fs = require('node:fs');
const path = require('node:path');
const { runCheck } = require('../src/checkers');

const inputFile = process.argv[2] || process.env.SMOKE_TARGETS_FILE || './local/smoke-targets.json';

function resolveInput(filePath) {
  if (path.isAbsolute(filePath)) {
    return filePath;
  }

  return path.resolve(process.cwd(), filePath);
}

function readTargets(filePath) {
  const resolved = resolveInput(filePath);

  if (!fs.existsSync(resolved)) {
    throw new Error(
      `Smoke targets file not found: ${resolved}\n` +
        'Create it locally (ignored by git), e.g. ./local/smoke-targets.json'
    );
  }

  const raw = fs.readFileSync(resolved, 'utf8');
  const parsed = JSON.parse(raw);

  if (!Array.isArray(parsed)) {
    throw new Error('Smoke targets file must contain a JSON array.');
  }

  return parsed;
}

function buildMonitor(target) {
  return {
    checkType: target.checkType,
    host: target.host || '',
    url: target.url || '',
    keyword: target.keyword || '',
    keywordCaseSensitive: Boolean(target.keywordCaseSensitive),
    httpStatusMode: target.httpStatusMode === '200' ? '200' : '2xx',
    tlsErrorAsFailure: target.tlsErrorAsFailure !== false,
    timeoutMs: Number(target.timeoutMs) || 10000
  };
}

function formatRow(columns) {
  return columns
    .map((value, index) => String(value).padEnd([30, 10, 36, 10, 20][index]))
    .join(' | ');
}

async function main() {
  const targets = readTargets(inputFile);

  console.log(`Smoke check started at ${new Date().toISOString()}\n`);
  console.log(formatRow(['Name', 'Type', 'Target', 'Result', 'Details']));
  console.log('-'.repeat(130));

  let failures = 0;

  for (const target of targets) {
    const monitor = buildMonitor(target);
    const result = await runCheck(monitor);

    const name = target.name || 'Unnamed';
    const checkType = target.checkType || 'unknown';
    const checkTarget = checkType === 'ping' ? target.host : target.url;
    const status = result.success ? 'PASS' : 'FAIL';

    if (!result.success) {
      failures += 1;
    }

    const details = result.success
      ? `status=${result.statusCode ?? 'n/a'} latency=${result.responseMs ?? 'n/a'}ms`
      : `${result.reason || 'check failed'} latency=${result.responseMs ?? 'n/a'}ms`;

    console.log(formatRow([name, checkType, checkTarget || '-', status, details]));
  }

  console.log(`\nCompleted with ${failures} failure(s).`);
  process.exitCode = failures > 0 ? 1 : 0;
}

main().catch((error) => {
  console.error(error.message || error);
  process.exitCode = 1;
});
