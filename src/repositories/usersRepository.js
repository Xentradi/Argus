function createUsersRepository(store) {
  return {
    hasUsers: () => store.hasUsers(),
    getSessionSecret: () => store.getSessionSecret(),
    createUser: ({ username, passwordHash, totpSecret }) =>
      store.createUser({
        username,
        passwordHash,
        totpSecret
      }),
    findUserByUsername: (username) => store.findUserByUsername(username),
    findUserById: (id) => store.findUserById(id)
  };
}

module.exports = {
  createUsersRepository
};
