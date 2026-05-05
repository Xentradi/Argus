function createMonitorsRepository(store) {
  return {
    listMonitors: (userId) => store.listMonitors(userId),
    getMonitorById: (id, userId) => store.getMonitorById(id, userId),
    getNextMonitorSortOrder: (groupId, userId) => store.getNextMonitorSortOrder(groupId, userId),
    createMonitor: (payload) => store.createMonitor(payload),
    updateMonitor: (id, patch, userId) => store.updateMonitor(id, patch, userId),
    updateMonitorRuntime: (id, runtimePatch) => store.updateMonitorRuntime(id, runtimePatch),
    deleteMonitor: (id, userId) => store.deleteMonitor(id, userId),
    moveMonitorInGroup: (id, direction, userId) => store.moveMonitorInGroup(id, direction, userId)
  };
}

module.exports = {
  createMonitorsRepository
};
