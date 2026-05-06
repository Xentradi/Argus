const { runPingCheck } = require('./checks/ping');
const { runHttpCheck } = require('./checks/http');
const { runKeywordCheck } = require('./checks/keyword');

async function runCheck(monitor) {
  if (monitor.checkType === 'ping') {
    return runPingCheck(monitor.host, monitor.timeoutMs);
  }

  if (monitor.checkType === 'keyword') {
    return runKeywordCheck(monitor);
  }

  return runHttpCheck(monitor);
}

module.exports = {
  runCheck
};
