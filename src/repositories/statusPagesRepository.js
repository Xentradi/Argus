function createStatusPagesRepository(store) {
  return {
    listStatusPages: (userId) => store.listStatusPages(userId),
    listMonitorsForStatusPage: (statusPageId) => store.listMonitorsForStatusPage(statusPageId),
    getStatusPageById: (id, userId) => store.getStatusPageById(id, userId),
    getStatusPageBySlug: (slug) => store.getStatusPageBySlug(slug),
    createStatusPage: ({ name, slug, monitorIds, userId }) =>
      store.createStatusPage({
        name,
        slug,
        monitorIds,
        userId
      }),
    deleteStatusPage: (id, userId) => store.deleteStatusPage(id, userId)
  };
}

module.exports = {
  createStatusPagesRepository
};
