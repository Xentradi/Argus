const { execFile } = require('child_process');
const config = require('../config');
const { buildSuccessResult, buildFailureResult } = require('./checkResult');

function nowIso() {
  return new Date().toISOString();
}

function extractPingTimeMs(text) {
  if (!text) {
    return null;
  }

  const match = text.match(/time[=<]([\d.]+)\s*ms/i);
  if (!match) {
    return null;
  }

  const value = Number.parseFloat(match[1]);
  return Number.isFinite(value) ? Math.round(value) : null;
}

function buildPingArgs(host, timeoutMs) {
  const probeCount = Math.max(1, Number.isFinite(config.pingProbeCount) ? config.pingProbeCount : 3);

  if (process.platform === 'win32') {
    return ['-n', String(probeCount), '-w', String(timeoutMs), host];
  }

  if (process.platform === 'darwin') {
    return ['-c', String(probeCount), '-W', String(timeoutMs), host];
  }

  const timeoutSeconds = Math.max(1, Math.ceil(timeoutMs / 1000));
  return ['-c', String(probeCount), '-W', String(timeoutSeconds), host];
}

function summarizePingFailure(output) {
  const text = String(output || '').trim();
  if (!text) {
    return null;
  }

  const unresolvedHostPattern =
    /unknown host|name or service not known|temporary failure in name resolution|cannot resolve|could not find host/i;
  if (unresolvedHostPattern.test(text)) {
    return 'Ping failed: host is not resolvable';
  }

  const packetsMatch = text.match(/(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets\s+)?received/i);
  if (packetsMatch) {
    const sent = Number.parseInt(packetsMatch[1], 10);
    const received = Number.parseInt(packetsMatch[2], 10);

    if (Number.isFinite(sent) && Number.isFinite(received)) {
      if (received === 0) {
        return `Ping failed: 100% packet loss (0/${sent} replies)`;
      }

      if (received < sent) {
        return `Ping unstable: ${sent - received}/${sent} packet loss`;
      }
    }
  }

  if (/timeout|timed out|request timeout/i.test(text)) {
    return 'Ping failed: request timed out';
  }

  if (/destination host unreachable|network is unreachable/i.test(text)) {
    return 'Ping failed: destination unreachable';
  }

  return null;
}

function parsePingPacketSummary(output) {
  const text = String(output || '').trim();
  if (!text) {
    return null;
  }

  const packetsMatch = text.match(/(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets\s+)?received/i);
  if (!packetsMatch) {
    return null;
  }

  const sent = Number.parseInt(packetsMatch[1], 10);
  const received = Number.parseInt(packetsMatch[2], 10);
  if (!Number.isFinite(sent) || !Number.isFinite(received)) {
    return null;
  }

  return { sent, received };
}

function runPingCheck(host, timeoutMs) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    const probeCount = Math.max(1, Number.isFinite(config.pingProbeCount) ? config.pingProbeCount : 3);
    const execTimeoutMs = timeoutMs * probeCount + 1000;

    execFile('ping', buildPingArgs(host, timeoutMs), { timeout: execTimeoutMs }, (error, stdout, stderr) => {
      const responseMs = Date.now() - startedAt;
      const checkedAt = nowIso();
      const output = [stdout, stderr].filter(Boolean).join('\n').trim();
      const packetSummary = parsePingPacketSummary(output);

      if (!error || (packetSummary && packetSummary.received > 0)) {
        resolve(
          buildSuccessResult({
            checkedAt,
            responseMs: extractPingTimeMs(output) || responseMs
          })
        );
        return;
      }

      let reason = summarizePingFailure(output) || output || error.message || 'Ping failed';

      if (error.code === 'ENOENT') {
        reason = 'ping command not found on uptime server';
      } else if (error.killed) {
        reason = `ping timed out after ${timeoutMs}ms`;
      }

      resolve(
        buildFailureResult({
          checkedAt,
          responseMs,
          reason
        })
      );
    });
  });
}

module.exports = {
  buildPingArgs,
  extractPingTimeMs,
  parsePingPacketSummary,
  summarizePingFailure,
  runPingCheck
};
