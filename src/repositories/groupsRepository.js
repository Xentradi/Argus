function createGroupsRepository(store) {
  return {
    listGroups: (userId) => store.listGroups(userId),
    getGroupById: (id, userId) => store.getGroupById(id, userId),
    createGroup: ({ name, webhookType, webhookUrl, userId }) =>
      store.createGroup({
        name,
        webhookType,
        webhookUrl,
        userId
      }),
    updateGroup: (id, patch, userId) => store.updateGroup(id, patch, userId),
    deleteGroup: (id, userId) => store.deleteGroup(id, userId)
  };
}

module.exports = {
  createGroupsRepository
};
