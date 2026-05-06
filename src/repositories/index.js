const { createUsersRepository } = require('./usersRepository');
const { createApiKeysRepository } = require('./apiKeysRepository');
const { createGroupsRepository } = require('./groupsRepository');
const { createMonitorsRepository } = require('./monitorsRepository');
const { createStatusPagesRepository } = require('./statusPagesRepository');
const { createIncidentsRepository } = require('./incidentsRepository');
const { createEventsRepository } = require('./eventsRepository');

function createRepositories(store) {
  const db = store.db;
  const users = createUsersRepository(db);
  const groups = createGroupsRepository(db);
  const monitors = createMonitorsRepository(db);
  const statusPages = createStatusPagesRepository(db);
  const incidents = createIncidentsRepository(db, monitors);
  const events = createEventsRepository(db, store.retentionDays);
  const apiKeys = createApiKeysRepository(db, users);

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
