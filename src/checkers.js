const { execFile } = require('child_process');
const https = require('https');
const axios = require('axios');

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
  if (process.platform === 'win32') {
    return ['-n', '1', '-w', String(timeoutMs), host];
  }

  if (process.platform === 'darwin') {
    return ['-c', '1', '-W', String(timeoutMs), host];
  }

  const timeoutSeconds = Math.max(1, Math.ceil(timeoutMs / 1000));
  return ['-c', '1', '-W', String(timeoutSeconds), host];
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

function runPingCheck(host, timeoutMs) {
  return new Promise((resolve) => {
    const startedAt = Date.now();

    execFile('ping', buildPingArgs(host, timeoutMs), { timeout: timeoutMs + 1000 }, (error, stdout, stderr) => {
      const responseMs = Date.now() - startedAt;
      const checkedAt = nowIso();

      if (!error) {
        resolve({
          success: true,
          checkedAt,
          responseMs: extractPingTimeMs(stdout) || responseMs,
          statusCode: null,
          keywordMatched: null,
          isTlsError: false,
          reason: null
        });
        return;
      }

      const output = [stdout, stderr].filter(Boolean).join('\n').trim();
      let reason = summarizePingFailure(output) || output || error.message || 'Ping failed';

      if (error.code === 'ENOENT') {
        reason = 'ping command not found on uptime server';
      } else if (error.killed) {
        reason = `ping timed out after ${timeoutMs}ms`;
      }

      resolve({
        success: false,
        checkedAt,
        responseMs,
        statusCode: null,
        keywordMatched: null,
        isTlsError: false,
        reason
      });
    });
  });
}

function isCertificateError(error) {
  const code = String(error && error.code ? error.code : '').toUpperCase();
  const message = String(error && error.message ? error.message : '').toLowerCase();

  return (
    code.includes('CERT') ||
    code.includes('SELF_SIGNED') ||
    message.includes('certificate') ||
    message.includes('ssl') ||
    message.includes('tls')
  );
}

async function runHttpBasedCheck(monitor, requireKeyword) {
  const checkedAt = nowIso();
  const startedAt = Date.now();

  try {
    const response = await axios.get(monitor.url, {
      timeout: monitor.timeoutMs,
      maxRedirects: 5,
      validateStatus: () => true,
      httpsAgent: new https.Agent({
        rejectUnauthorized: monitor.tlsErrorAsFailure
      })
    });

    const responseMs = Date.now() - startedAt;
    const statusCode = Number(response.status);

    const statusOk =
      monitor.httpStatusMode === '2xx'
        ? statusCode >= 200 && statusCode < 300
        : statusCode === 200;

    if (!statusOk) {
      return {
        success: false,
        checkedAt,
        responseMs,
        statusCode,
        keywordMatched: null,
        isTlsError: false,
        reason:
          monitor.httpStatusMode === '2xx'
            ? `HTTP ${statusCode} (expected 2xx)`
            : `HTTP ${statusCode} (expected 200)`
      };
    }

    if (!requireKeyword) {
      return {
        success: true,
        checkedAt,
        responseMs,
        statusCode,
        keywordMatched: null,
        isTlsError: false,
        reason: null
      };
    }

    const keyword = String(monitor.keyword || '');
    if (!keyword) {
      return {
        success: false,
        checkedAt,
        responseMs,
        statusCode,
        keywordMatched: false,
        isTlsError: false,
        reason: 'Keyword is empty'
      };
    }

    const bodyText = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    const haystack = monitor.keywordCaseSensitive ? bodyText : bodyText.toLowerCase();
    const needle = monitor.keywordCaseSensitive ? keyword : keyword.toLowerCase();
    const keywordMatched = haystack.includes(needle);

    if (!keywordMatched) {
      return {
        success: false,
        checkedAt,
        responseMs,
        statusCode,
        keywordMatched,
        isTlsError: false,
        reason: `Keyword \"${keyword}\" not found`
      };
    }

    return {
      success: true,
      checkedAt,
      responseMs,
      statusCode,
      keywordMatched,
      isTlsError: false,
      reason: null
    };
  } catch (error) {
    const responseMs = Date.now() - startedAt;
    const tlsError = isCertificateError(error);

    return {
      success: false,
      checkedAt,
      responseMs,
      statusCode: null,
      keywordMatched: null,
      isTlsError: tlsError,
      reason: error.message || 'HTTP request failed'
    };
  }
}

async function runCheck(monitor) {
  if (monitor.checkType === 'ping') {
    return runPingCheck(monitor.host, monitor.timeoutMs);
  }

  if (monitor.checkType === 'keyword') {
    return runHttpBasedCheck(monitor, true);
  }

  return runHttpBasedCheck(monitor, false);
}

module.exports = {
  runCheck
};
