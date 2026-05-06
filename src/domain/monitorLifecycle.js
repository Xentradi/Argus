const { runCheck } = require('../checkers');
const { sendWebhookAlert } = require('../alerts');
const { sleep } = require('../utils');
const {
  normalizeMonitorRuntime,
  buildRuntimePatch,
  buildRecoveryRuntimePatch
} = require('./monitorSnapshot');
const { normalizeLogger } = require('../observability/logger');

class MonitorLifecycle {
  constructor({
    store,
    normalIntervalMs,
    downIntervalMs,
    confirmationRetries,
    confirmationRetryIntervalMs,
    minDowntimeBeforeAlertMs,
    alertCooldownMs,
    keywordMinDowntimeMs,
    runCheckImpl = runCheck,
    sendWebhookAlertImpl = sendWebhookAlert,
    sleepImpl = sleep,
    logger = console
  }) {
    this.store = store;
    this.normalIntervalMs = normalIntervalMs;
    this.downIntervalMs = downIntervalMs;
    this.confirmationRetries = confirmationRetries;
    this.confirmationRetryIntervalMs = confirmationRetryIntervalMs;
    this.minDowntimeBeforeAlertMs = minDowntimeBeforeAlertMs;
    this.alertCooldownMs = alertCooldownMs;
    this.keywordMinDowntimeMs = keywordMinDowntimeMs;
    this.runCheck = runCheckImpl;
    this.sendWebhookAlert = sendWebhookAlertImpl;
    this.sleep = sleepImpl;
    this.logger = normalizeLogger(logger);
  }

  resolveCheckedAtMs(result) {
    if (result && result.checkedAt) {
      const parsed = new Date(result.checkedAt).getTime();
      if (Number.isFinite(parsed)) {
        return parsed;
      }
    }

    return Date.now();
  }

  resolveMinDowntimeMs(monitor) {
    if (Number.isFinite(monitor.minDowntimeMs)) {
      return Math.max(0, monitor.minDowntimeMs);
    }

    if (monitor.checkType === 'keyword') {
      return Math.max(0, this.keywordMinDowntimeMs || 0);
    }

    return Math.max(0, this.minDowntimeBeforeAlertMs || 0);
  }

  resolveAlertCooldownMs(monitor) {
    if (Number.isFinite(monitor.alertCooldownMs)) {
      return Math.max(0, monitor.alertCooldownMs);
    }

    return Math.max(0, this.alertCooldownMs || 0);
  }

  persistResult(monitorId, result, status) {
    const existingMonitor = this.store.getMonitorById(monitorId);
    if (!existingMonitor) {
      this.logger.warn('Skipping monitor result persistence for missing monitor', {
        monitorId,
        status
      });
      return;
    }

    const runtimePatch = buildRuntimePatch({
      monitor: existingMonitor,
      result,
      status
    });

    this.store.updateMonitorRuntime(monitorId, runtimePatch);
  }

  async confirmRetries(monitorId, expectSuccess, statusDuringConfirmation) {
    let lastResult = null;

    for (let attempt = 1; attempt <= this.confirmationRetries; attempt += 1) {
      await this.sleep(this.confirmationRetryIntervalMs);

      const monitor = this.store.getMonitorById(monitorId);
      if (!monitor || !monitor.active) {
        return {
          confirmed: false,
          cancelled: true,
          lastResult
        };
      }

      lastResult = await this.runCheck(monitor);
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
    const initialResult = await this.runCheck(monitor);

    if (initialResult.success) {
      this.persistResult(monitor.id, initialResult, 'up');
      return this.resolveNextDelay('up');
    }

    this.persistResult(monitor.id, initialResult, 'up');

    const confirmation = await this.confirmRetries(monitor.id, false, 'up');
    if (confirmation.cancelled || !confirmation.confirmed) {
      return this.resolveNextDelay('up');
    }

    const latestMonitor = this.store.getMonitorById(monitor.id);
    if (!latestMonitor || !latestMonitor.active) {
      return this.resolveNextDelay('up');
    }

    const downResult = confirmation.lastResult || initialResult;
    await this.markMonitorDown(latestMonitor, downResult);

    return this.resolveNextDelay('down');
  }

  async handleDownMonitor(monitor) {
    const initialResult = await this.runCheck(monitor);
    this.persistResult(monitor.id, initialResult, 'down');

    if (!initialResult.success) {
      await this.maybeSendDownAlert(monitor, initialResult);
      return this.resolveNextDelay('down');
    }

    const confirmation = await this.confirmRetries(monitor.id, true, 'down');
    if (confirmation.cancelled || !confirmation.confirmed) {
      return this.resolveNextDelay('down');
    }

    const latestMonitor = this.store.getMonitorById(monitor.id);
    if (!latestMonitor || !latestMonitor.active) {
      return this.resolveNextDelay('down');
    }

    const upResult = confirmation.lastResult || initialResult;
    await this.markMonitorRecovered(latestMonitor, upResult);

    return this.resolveNextDelay('up');
  }

  resolveNextDelay(status) {
    return status === 'down' ? this.downIntervalMs : this.normalIntervalMs;
  }

  async maybeSendDownAlert(monitor, result) {
    const incident = this.store.getOpenIncidentByMonitorId(monitor.id);
    if (!incident || incident.alertedAt) {
      return;
    }

    const nowMs = this.resolveCheckedAtMs(result);
    const startedMs = new Date(incident.startedAt).getTime();
    if (!Number.isFinite(startedMs)) {
      return;
    }

    const minDowntimeMs = this.resolveMinDowntimeMs(monitor);
    const downtimeMs = nowMs - startedMs;
    if (minDowntimeMs > 0 && downtimeMs < minDowntimeMs) {
      return;
    }

    const cooldownMs = this.resolveAlertCooldownMs(monitor);
    const lastAlertDownAt = normalizeMonitorRuntime(monitor).lastAlertDownAt;
    if (lastAlertDownAt && cooldownMs > 0) {
      const lastAlertMs = new Date(lastAlertDownAt).getTime();
      if (Number.isFinite(lastAlertMs) && nowMs - lastAlertMs < cooldownMs) {
        this.store.addEvent({
          userId: monitor.userId || null,
          monitorId: monitor.id,
          monitorName: monitor.name,
          eventType: 'alert_down_suppressed',
          message: 'Down alert suppressed (cooldown active)',
          details: {
            checkedAt: new Date(nowMs).toISOString(),
            cooldownRemainingSeconds: Math.ceil((cooldownMs - (nowMs - lastAlertMs)) / 1000)
          }
        });
        return;
      }
    }

    const at = new Date(nowMs).toISOString();
    const currentMonitor = this.store.getMonitorById(monitor.id);
    if (!currentMonitor) {
      this.logger.warn('Skipping down alert for missing monitor', {
        monitorId: monitor.id
      });
      return;
    }

    const alertResult = await this.sendWebhookAlert(currentMonitor, {
      type: 'down',
      at,
      reason: result.reason || 'Confirmed failure after retries'
    });

    if (alertResult.ok) {
      this.store.markIncidentAlerted(incident.id, at);
      this.store.updateMonitorRuntime(monitor.id, {
        lastAlertDownAt: at
      });
    }

    this.logger.info('alert_down_result', {
      monitorId: monitor.id,
      alerted: Boolean(alertResult.ok),
      skipped: Boolean(alertResult.skipped)
    });

    this.store.addEvent({
      userId: monitor.userId || null,
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
    if (openIncident) {
      this.logger.info('monitor_down_suppressed', {
        monitorId: monitor.id,
        reason: 'incident_already_open'
      });
      this.store.addEvent({
        userId: monitor.userId || null,
        monitorId: monitor.id,
        monitorName: monitor.name,
        eventType: 'monitor_down_suppressed',
        message: 'Suppressed duplicate down transition (incident already open)',
        details: {
          checkedAt: at
        }
      });
      return;
    }

    this.store.addIncident({
      userId: monitor.userId || null,
      monitorId: monitor.id,
      monitorName: monitor.name,
      startedAt: at,
      downReason: result.reason || 'Confirmed failure after retries'
    });

    this.logger.info('monitor_down', {
      monitorId: monitor.id,
      reason: result.reason || 'Confirmed failure after retries',
      responseMs: result.responseMs
    });

    this.store.addEvent({
      userId: monitor.userId || null,
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
  }

  async markMonitorRecovered(monitor, result) {
    const at = result.checkedAt || new Date().toISOString();
    const currentMonitor = this.store.getMonitorById(monitor.id);
    if (!currentMonitor) {
      this.logger.warn('Skipping recovery transition for missing monitor', {
        monitorId: monitor.id
      });
      return;
    }

    const recoveryPatch = buildRecoveryRuntimePatch({
      monitor: currentMonitor,
      result: {
        ...result,
        checkedAt: at
      }
    });

    this.store.updateMonitorRuntime(monitor.id, recoveryPatch);

    const closedIncident = this.store.closeOpenIncidentForMonitor(monitor.id, {
      endedAt: at,
      recoveryReason: 'Confirmed recovery after retries'
    });

    this.store.addEvent({
      userId: monitor.userId || null,
      monitorId: monitor.id,
      monitorName: monitor.name,
      eventType: 'monitor_recovered',
      message: 'Monitor recovered and returned to normal interval',
      details: {
        checkedAt: at,
        durationSeconds: closedIncident ? closedIncident.durationSeconds : null
      }
    });

    this.logger.info('monitor_recovered', {
      monitorId: monitor.id,
      alerted: Boolean(closedIncident && closedIncident.alertedAt)
    });

    const monitorAfterRecovery = this.store.getMonitorById(monitor.id);
    if (!monitorAfterRecovery) {
      return;
    }

    if (!closedIncident || !closedIncident.alertedAt) {
      this.logger.info('alert_recovery_suppressed', {
        monitorId: monitor.id,
        reason: 'no_down_alert'
      });
      this.store.addEvent({
        userId: monitor.userId || null,
        monitorId: monitor.id,
        monitorName: monitor.name,
        eventType: 'alert_recovery_suppressed',
        message: 'Recovery alert suppressed (no down alert sent)',
        details: {
          checkedAt: at,
          downAt: closedIncident ? closedIncident.startedAt : null
        }
      });
      return;
    }

    const alertResult = await this.sendWebhookAlert(monitorAfterRecovery, {
      type: 'recovery',
      at,
      downAt: closedIncident ? closedIncident.startedAt : null,
      durationSeconds: closedIncident ? closedIncident.durationSeconds : null,
      reason: 'Confirmed recovery after retries'
    });

    this.store.addEvent({
      userId: monitor.userId || null,
      monitorId: monitor.id,
      monitorName: monitor.name,
      eventType: alertResult.ok ? 'alert_recovery_sent' : 'alert_recovery_failed',
      message: alertResult.ok
        ? 'Recovery alert sent'
        : `Failed to send recovery alert: ${alertResult.error || 'unknown error'}`,
      details: {
        channel: monitorAfterRecovery.webhookType,
        skipped: Boolean(alertResult.skipped)
      }
    });

    this.logger.info('alert_recovery_result', {
      monitorId: monitor.id,
      alerted: Boolean(alertResult.ok),
      skipped: Boolean(alertResult.skipped)
    });
  }
}

module.exports = {
  MonitorLifecycle
};
