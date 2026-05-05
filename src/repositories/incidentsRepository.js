function createIncidentsRepository(store) {
  return {
    listIncidents: (limit, userId) => store.listIncidents(limit, userId),
    listOpenIncidents: (userId) => store.listOpenIncidents(userId),
    addIncident: (payload) => store.addIncident(payload),
    getOpenIncidentByMonitorId: (monitorId) => store.getOpenIncidentByMonitorId(monitorId),
    closeIncident: (id, details) => store.closeIncident(id, details),
    markIncidentAlerted: (id, alertedAt) => store.markIncidentAlerted(id, alertedAt),
    closeOpenIncidentForMonitor: (monitorId, details) => store.closeOpenIncidentForMonitor(monitorId, details),
    getLatestRecoveryTimesByMonitorIds: (monitorIds) => store.getLatestRecoveryTimesByMonitorIds(monitorIds),
    calculateMonitorUptimeStats: (monitorId, since, userId) =>
      store.calculateMonitorUptimeStats(monitorId, since, userId)
  };
}

module.exports = {
  createIncidentsRepository
};
