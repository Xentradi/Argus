const { createMonitorValidation } = require('./monitors');
const { createGroupValidation } = require('./groups');
const { createStatusPageValidation } = require('./statusPages');

module.exports = {
  createMonitorValidation,
  createGroupValidation,
  createStatusPageValidation
};
