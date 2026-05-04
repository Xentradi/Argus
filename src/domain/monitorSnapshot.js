function normalizeMonitorRuntime(monitor) {
  const runtime = monitor && monitor.runtime ? monitor.runtime : {};

  return {
    status: runtime.status || 'unknown',
    lastCheckAt: runtime.lastCheckAt || null,
    firstSuccessAt: runtime.firstSuccessAt || null,
    lastSuccessAt: runtime.lastSuccessAt || null,
    lastFailureAt: runtime.lastFailureAt || null,
    lastError: runtime.lastError || null,
    lastResponseMs: Number.isFinite(runtime.lastResponseMs) ? Math.round(runtime.lastResponseMs) : null,
    lastHttpStatus:
      runtime.lastHttpStatus === null || runtime.lastHttpStatus === undefined ? null : Number(runtime.lastHttpStatus),
    lastKeywordMatched:
      runtime.lastKeywordMatched === null || runtime.lastKeywordMatched === undefined
        ? null
        : Boolean(runtime.lastKeywordMatched),
    lastTlsError: Boolean(runtime.lastTlsError),
    lastAlertDownAt: runtime.lastAlertDownAt || null,
    nextCheckAt: runtime.nextCheckAt || null
  };
}

function buildRuntimePatch({ monitor, result, status }) {
  const existingRuntime = normalizeMonitorRuntime(monitor);
  const runtimePatch = {
    status,
    lastCheckAt: result.checkedAt,
    lastError: result.success ? null : result.reason || 'Check failed',
    lastResponseMs: Number.isFinite(result.responseMs) ? Math.round(result.responseMs) : null,
    lastHttpStatus:
      result.statusCode === null || result.statusCode === undefined ? null : Number(result.statusCode),
    lastKeywordMatched:
      result.keywordMatched === null || result.keywordMatched === undefined ? null : Boolean(result.keywordMatched),
    lastTlsError: Boolean(result.isTlsError),
    nextCheckAt: null
  };

  if (result.success) {
    runtimePatch.lastSuccessAt = result.checkedAt;
    runtimePatch.firstSuccessAt = existingRuntime.firstSuccessAt || result.checkedAt;
  } else {
    runtimePatch.lastFailureAt = result.checkedAt;
  }

  return runtimePatch;
}

function buildRecoveryRuntimePatch({ monitor, result }) {
  const existingRuntime = normalizeMonitorRuntime(monitor);
  const at = result.checkedAt || new Date().toISOString();

  return {
    status: 'up',
    lastCheckAt: at,
    firstSuccessAt: existingRuntime.firstSuccessAt || at,
    lastSuccessAt: at,
    lastError: null,
    lastResponseMs: Number.isFinite(result.responseMs) ? Math.round(result.responseMs) : null,
    lastHttpStatus:
      result.statusCode === null || result.statusCode === undefined ? null : Number(result.statusCode),
    lastKeywordMatched:
      result.keywordMatched === null || result.keywordMatched === undefined ? null : Boolean(result.keywordMatched),
    lastTlsError: Boolean(result.isTlsError),
    nextCheckAt: null
  };
}

module.exports = {
  normalizeMonitorRuntime,
  buildRuntimePatch,
  buildRecoveryRuntimePatch
};
