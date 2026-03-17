const { runCheck } = require('./checkers');
const { sendWebhookAlert } = require('./alerts');
const { sleep } = require('./utils');

class MonitorEngine {
  constructor({
    store,
    normalIntervalMs,
    downIntervalMs,
    confirmationRetries,
    confirmationRetryIntervalMs,
    logger = console
  }) {
    this.store = store;
    this.normalIntervalMs = normalIntervalMs;
    this.downIntervalMs = downIntervalMs;
    this.confirmationRetries = confirmationRetries;
    this.confirmationRetryIntervalMs = confirmationRetryIntervalMs;
    this.logger = logger;

    this.running = false;
    this.timers = new Map();
    this.retentionTimer = null;
  }

  start() {
    if (this.running) {
      return;
    }

    this.running = true;
    this.syncMonitors();

    this.retentionTimer = setInterval(() => {
      try {
        this.store.pruneOldHistory();
      } catch (error) {
        this.logger.error('Failed to prune old history', error);
      }
    }, 24 * 60 * 60 * 1000);

    this.retentionTimer.unref?.();
  }

  stop() {
    this.running = false;

    for (const timer of this.timers.values()) {
      clearTimeout(timer);
    }

    this.timers.clear();

    if (this.retentionTimer) {
      clearInterval(this.retentionTimer);
      this.retentionTimer = null;
    }
  }

  syncMonitors() {
    if (!this.running) {
      return;
    }

    const activeMonitors = this.store.listMonitors().filter((monitor) => monitor.active);
    const activeIds = new Set(activeMonitors.map((monitor) => monitor.id));

    for (const monitor of activeMonitors) {
      if (!this.timers.has(monitor.id)) {
        this.schedule(monitor.id, 1000);
      }
    }

    for (const [monitorId, timer] of this.timers.entries()) {
      if (activeIds.has(monitorId)) {
        continue;
      }

      clearTimeout(timer);
      this.timers.delete(monitorId);

      const monitor = this.store.getMonitorById(monitorId);
      if (monitor) {
        this.store.updateMonitorRuntime(monitorId, {
          nextCheckAt: null
        });
      }
    }
  }

  schedule(monitorId, delayMs) {
    if (!this.running) {
      return;
    }

    const existing = this.timers.get(monitorId);
    if (existing) {
      clearTimeout(existing);
    }

    const nextCheckAt = new Date(Date.now() + delayMs).toISOString();
    this.store.updateMonitorRuntime(monitorId, {
      nextCheckAt
    });

    const timer = setTimeout(() => {
      this.timers.delete(monitorId);
      this.executeMonitor(monitorId).catch((error) => {
        this.logger.error(`Unhandled monitor execution error (${monitorId})`, error);
        this.store.updateMonitorRuntime(monitorId, {
          lastError: error.message || 'Unhandled monitor engine error',
          nextCheckAt: null
        });

        const monitor = this.store.getMonitorById(monitorId);
        if (!monitor || !monitor.active) {
          return;
        }

        const nextDelay = monitor.runtime.status === 'down' ? this.downIntervalMs : this.normalIntervalMs;
        this.schedule(monitorId, nextDelay);
      });
    }, delayMs);

    timer.unref?.();
    this.timers.set(monitorId, timer);
  }

  async executeMonitor(monitorId) {
    if (!this.running) {
      return;
    }

    const monitor = this.store.getMonitorById(monitorId);
    if (!monitor || !monitor.active) {
      return;
    }

    const nextDelay =
      monitor.runtime.status === 'down'
        ? await this.handleDownMonitor(monitor)
        : await this.handleUpMonitor(monitor);

    const latest = this.store.getMonitorById(monitorId);
    if (!latest || !latest.active) {
      return;
    }

    this.schedule(monitorId, nextDelay);
  }

  persistResult(monitorId, result, status) {
    const runtimePatch = {
      status,
      lastCheckAt: result.checkedAt,
      lastError: result.success ? null : result.reason || 'Check failed',
      lastResponseMs: Number.isFinite(result.responseMs) ? Math.round(result.responseMs) : null,
      lastHttpStatus:
        result.statusCode === null || result.statusCode === undefined ? null : Number(result.statusCode),
      lastKeywordMatched:
        result.keywordMatched === null || result.keywordMatched === undefined
          ? null
          : Boolean(result.keywordMatched),
      lastTlsError: Boolean(result.isTlsError),
      nextCheckAt: null
    };

    if (result.success) {
      runtimePatch.lastSuccessAt = result.checkedAt;
    } else {
      runtimePatch.lastFailureAt = result.checkedAt;
    }

    this.store.updateMonitorRuntime(monitorId, runtimePatch);
  }

  async confirmRetries(monitorId, expectSuccess, statusDuringConfirmation) {
    let lastResult = null;

    for (let attempt = 1; attempt <= this.confirmationRetries; attempt += 1) {
      await sleep(this.confirmationRetryIntervalMs);

      const monitor = this.store.getMonitorById(monitorId);
      if (!monitor || !monitor.active) {
        return {
          confirmed: false,
          cancelled: true,
          lastResult
        };
      }

      lastResult = await runCheck(monitor);
      this.persistResult(monitor.id, lastResult, statusDuringConfirmation);

      if (expectSuccess && !lastResult.success) {
        return {
          confirmed: false,
          cancelled: false,
          lastResult
        };
      }

      if (!expectSuccess && lastResult.success) {
        return {
          confirmed: false,
          cancelled: false,
          lastResult
        };
      }
    }

    return {
      confirmed: true,
      cancelled: false,
      lastResult
    };
  }

  async handleUpMonitor(monitor) {
    const initialResult = await runCheck(monitor);

    if (initialResult.success) {
      this.persistResult(monitor.id, initialResult, 'up');
      return this.normalIntervalMs;
    }

    this.persistResult(monitor.id, initialResult, 'up');

    const confirmation = await this.confirmRetries(monitor.id, false, 'up');
    if (confirmation.cancelled) {
      return this.normalIntervalMs;
    }

    if (!confirmation.confirmed) {
      return this.normalIntervalMs;
    }

    const latestMonitor = this.store.getMonitorById(monitor.id);
    if (!latestMonitor || !latestMonitor.active) {
      return this.normalIntervalMs;
    }

    const downResult = confirmation.lastResult || initialResult;
    await this.markMonitorDown(latestMonitor, downResult);

    return this.downIntervalMs;
  }

  async handleDownMonitor(monitor) {
    const initialResult = await runCheck(monitor);
    this.persistResult(monitor.id, initialResult, 'down');

    if (!initialResult.success) {
      return this.downIntervalMs;
    }

    const confirmation = await this.confirmRetries(monitor.id, true, 'down');
    if (confirmation.cancelled) {
      return this.downIntervalMs;
    }

    if (!confirmation.confirmed) {
      return this.downIntervalMs;
    }

    const latestMonitor = this.store.getMonitorById(monitor.id);
    if (!latestMonitor || !latestMonitor.active) {
      return this.downIntervalMs;
    }

    const upResult = confirmation.lastResult || initialResult;
    await this.markMonitorRecovered(latestMonitor, upResult);

    return this.normalIntervalMs;
  }

  async markMonitorDown(monitor, result) {
    const at = result.checkedAt || new Date().toISOString();

    this.store.updateMonitorRuntime(monitor.id, {
      status: 'down',
      lastCheckAt: at,
      lastFailureAt: at,
      lastError: result.reason || 'Check failed',
      lastResponseMs: Number.isFinite(result.responseMs) ? Math.round(result.responseMs) : null,
      lastHttpStatus:
        result.statusCode === null || result.statusCode === undefined ? null : Number(result.statusCode),
      lastKeywordMatched:
        result.keywordMatched === null || result.keywordMatched === undefined
          ? null
          : Boolean(result.keywordMatched),
      lastTlsError: Boolean(result.isTlsError),
      nextCheckAt: null
    });

    const openIncident = this.store.getOpenIncidentByMonitorId(monitor.id);
    if (!openIncident) {
      this.store.addIncident({
        monitorId: monitor.id,
        monitorName: monitor.name,
        startedAt: at,
        downReason: result.reason || 'Confirmed failure after retries'
      });
    }

    this.store.addEvent({
      monitorId: monitor.id,
      monitorName: monitor.name,
      eventType: 'monitor_down',
      message: `Monitor marked down: ${result.reason || 'Unknown failure'}`,
      details: {
        checkedAt: at,
        responseMs: result.responseMs,
        statusCode: result.statusCode,
        isTlsError: Boolean(result.isTlsError)
      }
    });

    const currentMonitor = this.store.getMonitorById(monitor.id);
    if (!currentMonitor) {
      return;
    }

    const alertResult = await sendWebhookAlert(currentMonitor, {
      type: 'down',
      at,
      reason: result.reason || 'Confirmed failure after retries'
    });

    this.store.addEvent({
      monitorId: monitor.id,
      monitorName: monitor.name,
      eventType: alertResult.ok ? 'alert_down_sent' : 'alert_down_failed',
      message: alertResult.ok
        ? 'Down alert sent'
        : `Failed to send down alert: ${alertResult.error || 'unknown error'}`,
      details: {
        channel: currentMonitor.webhookType,
        skipped: Boolean(alertResult.skipped)
      }
    });
  }

  async markMonitorRecovered(monitor, result) {
    const at = result.checkedAt || new Date().toISOString();

    this.store.updateMonitorRuntime(monitor.id, {
      status: 'up',
      lastCheckAt: at,
      lastSuccessAt: at,
      lastError: null,
      lastResponseMs: Number.isFinite(result.responseMs) ? Math.round(result.responseMs) : null,
      lastHttpStatus:
        result.statusCode === null || result.statusCode === undefined ? null : Number(result.statusCode),
      lastKeywordMatched:
        result.keywordMatched === null || result.keywordMatched === undefined
          ? null
          : Boolean(result.keywordMatched),
      lastTlsError: Boolean(result.isTlsError),
      nextCheckAt: null
    });

    const closedIncident = this.store.closeOpenIncidentForMonitor(monitor.id, {
      endedAt: at,
      recoveryReason: 'Confirmed recovery after retries'
    });

    this.store.addEvent({
      monitorId: monitor.id,
      monitorName: monitor.name,
      eventType: 'monitor_recovered',
      message: 'Monitor recovered and returned to normal interval',
      details: {
        checkedAt: at,
        durationSeconds: closedIncident ? closedIncident.durationSeconds : null
      }
    });

    const currentMonitor = this.store.getMonitorById(monitor.id);
    if (!currentMonitor) {
      return;
    }

    const alertResult = await sendWebhookAlert(currentMonitor, {
      type: 'recovery',
      at,
      durationSeconds: closedIncident ? closedIncident.durationSeconds : null,
      reason: 'Confirmed recovery after retries'
    });

    this.store.addEvent({
      monitorId: monitor.id,
      monitorName: monitor.name,
      eventType: alertResult.ok ? 'alert_recovery_sent' : 'alert_recovery_failed',
      message: alertResult.ok
        ? 'Recovery alert sent'
        : `Failed to send recovery alert: ${alertResult.error || 'unknown error'}`,
      details: {
        channel: currentMonitor.webhookType,
        skipped: Boolean(alertResult.skipped)
      }
    });
  }
}

module.exports = {
  MonitorEngine
};
