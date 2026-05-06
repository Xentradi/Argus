const { clampNumber } = require('../utils');

function monitorTarget(monitor) {
  return monitor.checkType === 'ping' ? monitor.host : monitor.url;
}

function elapsedSecondsSince(isoDate, nowMs = Date.now()) {
  const startedMs = new Date(isoDate).getTime();
  if (!Number.isFinite(startedMs)) {
    return null;
  }

  if (nowMs < startedMs) {
    return 0;
  }

  return Math.round((nowMs - startedMs) / 1000);
}

function buildDashboardSnapshot(
  store,
  { userId = null, eventsPage = 1, includeEvents = true, includeIncidents = true, nowMs = Date.now() } = {}
) {
  const monitors = store.listMonitors(userId);
  const groups = store.listGroups(userId);
  const groupsById = new Map(groups.map((group) => [group.id, group]));
  const openIncidentsByMonitorId = new Map(store.listOpenIncidents(userId).map((incident) => [incident.monitorId, incident]));
  const groupedMap = new Map();
  const serializedMonitors = [];

  for (const monitor of monitors) {
    const effectiveGroup = monitor.groupId ? groupsById.get(monitor.groupId) : null;
    const bucketKey = effectiveGroup ? effectiveGroup.id : 'ungrouped';
    const bucketName = effectiveGroup ? effectiveGroup.name : 'Ungrouped';
    const status = monitor.runtime.status || 'unknown';
    const isPaused = !monitor.active;
    const statusClass = isPaused ? 'paused' : status;
    const hasUnconfirmedFailures = !isPaused && status === 'up' && Boolean(monitor.runtime.lastError);
    const displayStatus = isPaused ? 'paused' : hasUnconfirmedFailures ? 'up (confirming)' : status;
    const openIncident = openIncidentsByMonitorId.get(monitor.id) || null;
    const downSince = openIncident
      ? openIncident.startedAt
      : status === 'down'
        ? monitor.runtime.lastFailureAt || monitor.runtime.lastCheckAt || null
        : null;
    const outageSeconds = downSince ? elapsedSecondsSince(downSince, nowMs) : null;

    const dashboardMonitor = {
      id: monitor.id,
      name: monitor.name,
      groupId: effectiveGroup ? effectiveGroup.id : null,
      groupName: bucketName,
      sortOrder: monitor.sortOrder || 0,
      checkType: monitor.checkType,
      target: monitorTarget(monitor) || '-',
      active: monitor.active,
      statusClass,
      displayStatus,
      runtime: {
        status,
        lastCheckAt: monitor.runtime.lastCheckAt || null,
        nextCheckAt: monitor.runtime.nextCheckAt || null,
        lastError: monitor.runtime.lastError || null,
        lastResponseMs: monitor.runtime.lastResponseMs,
        lastHttpStatus: monitor.runtime.lastHttpStatus,
        lastKeywordMatched: monitor.runtime.lastKeywordMatched,
        lastFailureAt: monitor.runtime.lastFailureAt || null,
        lastSuccessAt: monitor.runtime.lastSuccessAt || null
      },
      hasUnconfirmedFailures,
      outage: {
        active: !isPaused && status === 'down',
        startedAt: downSince,
        durationSeconds: !isPaused && status === 'down' ? outageSeconds : null
      }
    };

    serializedMonitors.push(dashboardMonitor);

    if (!groupedMap.has(bucketKey)) {
      groupedMap.set(bucketKey, {
        groupId: effectiveGroup ? effectiveGroup.id : null,
        groupName: bucketName,
        monitors: []
      });
    }
    groupedMap.get(bucketKey).monitors.push(dashboardMonitor);
  }

  const groupedMonitors = Array.from(groupedMap.values())
    .sort((left, right) => {
      if (!left.groupId && right.groupId) {
        return 1;
      }
      if (left.groupId && !right.groupId) {
        return -1;
      }
      return left.groupName.localeCompare(right.groupName);
    })
    .map((group) => ({
      ...group,
      monitors: group.monitors
        .slice()
        .sort(
          (left, right) =>
            (left.sortOrder || 0) - (right.sortOrder || 0) || left.name.localeCompare(right.name)
        )
    }));

  const summary = {
    total: serializedMonitors.length,
    groups: groupedMonitors.length,
    up: serializedMonitors.filter((monitor) => monitor.statusClass === 'up').length,
    down: serializedMonitors.filter((monitor) => monitor.statusClass === 'down').length,
    unknown: serializedMonitors.filter((monitor) => monitor.statusClass === 'unknown' || monitor.statusClass === 'paused').length
  };

  const activeOutages = serializedMonitors
    .filter((monitor) => monitor.active && monitor.runtime.status === 'down')
    .map((monitor) => ({
      monitorId: monitor.id,
      monitorName: monitor.name,
      groupName: monitor.groupName,
      target: monitor.target,
      downSince: monitor.outage.startedAt,
      durationSeconds: monitor.outage.durationSeconds,
      reason: monitor.runtime.lastError || 'No failure details'
    }))
    .sort((left, right) => (right.durationSeconds || 0) - (left.durationSeconds || 0));

  const snapshot = {
    generatedAt: new Date(nowMs).toISOString(),
    summary,
    groupedMonitors,
    activeOutages
  };

  if (includeIncidents) {
    const incidents = store.listIncidents(250, userId).map((incident) => {
      if (incident.endedAt || !incident.startedAt) {
        return incident;
      }
      return {
        ...incident,
        durationSeconds: elapsedSecondsSince(incident.startedAt, nowMs)
      };
    });

    const incidentsByMonitor = {};
    for (const incident of incidents) {
      if (!incidentsByMonitor[incident.monitorId]) {
        incidentsByMonitor[incident.monitorId] = [];
      }

      if (incidentsByMonitor[incident.monitorId].length < 8) {
        incidentsByMonitor[incident.monitorId].push(incident);
      }
    }

    snapshot.incidents = incidents;
    snapshot.incidentsByMonitor = incidentsByMonitor;
  }

  if (includeEvents) {
    const requestedEventsPage = clampNumber(eventsPage, 1, 1000000, 1);
    const eventsPerPage = 20;
    const totalEvents = store.countEvents(userId);
    const totalEventPages = Math.max(1, Math.ceil(totalEvents / eventsPerPage));
    const safeEventsPage = Math.min(requestedEventsPage, totalEventPages);
    const eventsOffset = (safeEventsPage - 1) * eventsPerPage;

    snapshot.events = store.listEvents(eventsPerPage, eventsOffset, userId);
    const operationalEventTypes = new Set([
      'monitor_down',
      'monitor_recovered',
      'alert_down_sent',
      'alert_down_failed',
      'alert_down_suppressed',
      'alert_recovery_sent',
      'alert_recovery_failed',
      'alert_recovery_suppressed',
      'manual_alert_sent',
      'manual_alert_failed'
    ]);
    snapshot.operationalEvents = snapshot.events.filter((event) => operationalEventTypes.has(event.eventType));
    snapshot.eventPagination = {
      page: safeEventsPage,
      totalPages: totalEventPages,
      hasPrev: safeEventsPage > 1,
      hasNext: safeEventsPage < totalEventPages
    };
  }

  return snapshot;
}

module.exports = {
  buildDashboardSnapshot,
  monitorTarget,
  elapsedSecondsSince
};
