function createEventsRepository(store) {
  return {
    addEvent: (payload) => store.addEvent(payload),
    countEvents: (userId) => store.countEvents(userId),
    listEvents: (limit, offset, userId) => store.listEvents(limit, offset, userId),
    pruneOldHistory: () => store.pruneOldHistory()
  };
}

module.exports = {
  createEventsRepository
};
