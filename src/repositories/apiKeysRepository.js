function createApiKeysRepository(store) {
  return {
    createApiKey: ({ userId, name }) => store.createApiKey({ userId, name }),
    authenticateApiKey: (token) => store.authenticateApiKey(token)
  };
}

module.exports = {
  createApiKeysRepository
};
