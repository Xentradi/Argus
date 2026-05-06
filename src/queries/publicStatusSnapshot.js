const { elapsedSecondsSince } = require('./dashboardSnapshot');

function formatUptimePercent(ratio) {
  if (!Number.isFinite(ratio)) {
    return 'N/A';
  }

  const percent = Math.max(0, Math.min(100, ratio * 100));
  return `${percent.toFixed(3)}%`;
}

function buildPublicStatusSnapshot(store, slug, { nowMs = Date.now() } = {}) {
  const statusPage = store.getStatusPageBySlug(slug);
  if (!statusPage) {
    return null;
  }

  const openIncidentsByMonitorId = new Map(
    store.listOpenIncidents(statusPage.userId || null).map((incident) => [incident.monitorId, incident])
  );
  const recoveryTimesByMonitorId = store.getLatestRecoveryTimesByMonitorIds(statusPage.monitors.map((monitor) => monitor.id));
  const monitors = statusPage.monitors.map((monitor) => {
    const uptime = store.calculateMonitorUptimeStats(monitor.id, undefined, statusPage.userId || null);
    const uptimeRatio = uptime && Number.isFinite(uptime.uptimeRatio) ? Math.max(0, Math.min(1, uptime.uptimeRatio)) : null;
    const status = monitor.runtime.status || 'unknown';
    const openIncident = openIncidentsByMonitorId.get(monitor.id) || null;
    const lastRecoveryAt = recoveryTimesByMonitorId[monitor.id] || null;
    const stateSince =
      status === 'down'
        ? openIncident
          ? openIncident.startedAt
          : monitor.runtime.lastFailureAt || monitor.runtime.lastCheckAt || null
        : status === 'up'
          ? lastRecoveryAt || monitor.runtime.firstSuccessAt || monitor.createdAt || null
          : monitor.runtime.lastCheckAt || null;

    return {
      id: monitor.id,
      name: monitor.name,
      status,
      uptimePercent: formatUptimePercent(uptimeRatio),
      uptimeRatio,
      stateSince,
      stateDurationSeconds: stateSince ? elapsedSecondsSince(stateSince, nowMs) : null
    };
  });

  return {
    generatedAt: new Date(nowMs).toISOString(),
    uptimeGoalPercent: 99.999,
    statusPage: {
      id: statusPage.id,
      slug: statusPage.slug,
      name: statusPage.name
    },
    monitors,
    summary: {
      total: monitors.length,
      up: monitors.filter((monitor) => monitor.status === 'up').length,
      down: monitors.filter((monitor) => monitor.status === 'down').length,
      unknown: monitors.filter((monitor) => monitor.status === 'unknown').length
    }
  };
}

module.exports = {
  buildPublicStatusSnapshot,
  formatUptimePercent
};
