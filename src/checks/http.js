const https = require('https');
const axios = require('axios');
const { buildSuccessResult, buildFailureResult } = require('./checkResult');

function nowIso() {
  return new Date().toISOString();
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

async function runHttpCheck(monitor) {
  const probe = await runHttpProbe(monitor);
  if (!probe.success) {
    return probe.result;
  }

  return buildSuccessResult({
    checkedAt: probe.checkedAt,
    responseMs: probe.responseMs,
    statusCode: probe.statusCode
  });
}

async function runHttpProbe(monitor) {
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
        result: buildFailureResult({
          checkedAt,
          responseMs,
          statusCode,
          reason:
            monitor.httpStatusMode === '2xx'
              ? `HTTP ${statusCode} (expected 2xx)`
              : `HTTP ${statusCode} (expected 200)`
        })
      };
    }

    return {
      success: true,
      checkedAt,
      responseMs,
      statusCode,
      bodyText: typeof response.data === 'string' ? response.data : JSON.stringify(response.data)
    };
  } catch (error) {
    const responseMs = Date.now() - startedAt;

    return {
      success: false,
      result: buildFailureResult({
        checkedAt,
        responseMs,
        isTlsError: isCertificateError(error),
        reason: error.message || 'HTTP request failed'
      })
    };
  }
}

module.exports = {
  isCertificateError,
  runHttpProbe,
  runHttpCheck
};
