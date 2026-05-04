const { MonitorLifecycle } = require('./domain/monitorLifecycle');

class MonitorEngine {
  constructor({
    store,
    normalIntervalMs,
    downIntervalMs,
    confirmationRetries,
    confirmationRetryIntervalMs,
    minDowntimeBeforeAlertMs,
    alertCooldownMs,
    keywordMinDowntimeMs,
    logger = console
  }) {
    this.store = store;
    this.normalIntervalMs = normalIntervalMs;
    this.downIntervalMs = downIntervalMs;
    this.logger = logger;
    this.lifecycle = new MonitorLifecycle({
      store,
      normalIntervalMs,
      downIntervalMs,
      confirmationRetries,
      confirmationRetryIntervalMs,
      minDowntimeBeforeAlertMs,
      alertCooldownMs,
      keywordMinDowntimeMs,
      logger
    });

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
    this.lifecycle.persistResult(monitorId, result, status);
  }

  async confirmRetries(monitorId, expectSuccess, statusDuringConfirmation) {
    return this.lifecycle.confirmRetries(monitorId, expectSuccess, statusDuringConfirmation);
  }

  async handleUpMonitor(monitor) {
    return this.lifecycle.handleUpMonitor(monitor);
  }

  async handleDownMonitor(monitor) {
    return this.lifecycle.handleDownMonitor(monitor);
  }
}

module.exports = {
  MonitorEngine
};
