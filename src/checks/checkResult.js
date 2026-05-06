function nowIso() {
  return new Date().toISOString();
}

function normalizeCheckResult(result) {
  const checkedAt = result.checkedAt || nowIso();

  return {
    success: Boolean(result.success),
    checkedAt,
    responseMs: Number.isFinite(result.responseMs) ? Math.round(result.responseMs) : null,
    statusCode:
      result.statusCode === null || result.statusCode === undefined ? null : Number(result.statusCode),
    keywordMatched:
      result.keywordMatched === null || result.keywordMatched === undefined
        ? null
        : Boolean(result.keywordMatched),
    isTlsError: Boolean(result.isTlsError),
    reason: result.reason || null
  };
}

function buildSuccessResult(fields = {}) {
  return normalizeCheckResult({
    success: true,
    checkedAt: fields.checkedAt,
    responseMs: fields.responseMs,
    statusCode: fields.statusCode,
    keywordMatched: fields.keywordMatched,
    isTlsError: false,
    reason: null
  });
}

function buildFailureResult(fields = {}) {
  return normalizeCheckResult({
    success: false,
    checkedAt: fields.checkedAt,
    responseMs: fields.responseMs,
    statusCode: fields.statusCode,
    keywordMatched: fields.keywordMatched,
    isTlsError: fields.isTlsError,
    reason: fields.reason
  });
}

module.exports = {
  normalizeCheckResult,
  buildSuccessResult,
  buildFailureResult
};
