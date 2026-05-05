const { createUsersRepository } = require('./usersRepository');
const { createApiKeysRepository } = require('./apiKeysRepository');
const { createGroupsRepository } = require('./groupsRepository');
const { createMonitorsRepository } = require('./monitorsRepository');
const { createStatusPagesRepository } = require('./statusPagesRepository');
const { createIncidentsRepository } = require('./incidentsRepository');
const { createEventsRepository } = require('./eventsRepository');

function createRepositories(store) {
  const users = createUsersRepository(store);
  const apiKeys = createApiKeysRepository(store);
  const groups = createGroupsRepository(store);
  const monitors = createMonitorsRepository(store);
  const statusPages = createStatusPagesRepository(store);
  const incidents = createIncidentsRepository(store);
  const events = createEventsRepository(store);

  return {
    users,
    apiKeys,
    groups,
    monitors,
    statusPages,
    incidents,
    events,
    ...users,
    ...apiKeys,
    ...groups,
    ...monitors,
    ...statusPages,
    ...incidents,
    ...events
  };
}

module.exports = {
  createRepositories
};
