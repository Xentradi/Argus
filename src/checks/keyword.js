const { runHttpProbe } = require('./http');
const { buildSuccessResult, buildFailureResult } = require('./checkResult');

async function runKeywordCheck(monitor) {
  const probe = await runHttpProbe(monitor);
  if (!probe.success) {
    return probe.result;
  }

  const keyword = String(monitor.keyword || '');
  if (!keyword) {
    return buildFailureResult({
      checkedAt: probe.checkedAt,
      responseMs: probe.responseMs,
      statusCode: probe.statusCode,
      keywordMatched: false,
      reason: 'Keyword is empty'
    });
  }

  const bodyText = probe.bodyText || '';
  const haystack = monitor.keywordCaseSensitive ? bodyText : bodyText.toLowerCase();
  const needle = monitor.keywordCaseSensitive ? keyword : keyword.toLowerCase();
  const keywordMatched = haystack.includes(needle);

  if (!keywordMatched) {
    return buildFailureResult({
      checkedAt: probe.checkedAt,
      responseMs: probe.responseMs,
      statusCode: probe.statusCode,
      keywordMatched,
      reason: `Keyword "${keyword}" not found`
    });
  }

  return buildSuccessResult({
    checkedAt: probe.checkedAt,
    responseMs: probe.responseMs,
    statusCode: probe.statusCode,
    keywordMatched
  });
}

module.exports = {
  runKeywordCheck
};
