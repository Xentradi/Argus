function normalizeSlug(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

function createStatusPageValidation() {
  function parseStatusPageForm(body) {
    const errors = [];
    const input = body && typeof body === 'object' ? body : {};
    const name = String(input.name || '').trim();
    const slug = normalizeSlug(input.slug || input.name || '');

    const selectedMonitorIds = Array.isArray(input.monitorIds)
      ? input.monitorIds
      : input.monitorIds
        ? [input.monitorIds]
        : [];
    const monitorIds = selectedMonitorIds.map((id) => String(id || '').trim()).filter(Boolean);

    if (!name) {
      errors.push('Status page name is required.');
    }

    if (!slug) {
      errors.push('Status page slug is required.');
    } else if (!/^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$/.test(slug)) {
      errors.push('Status page slug must be 1-80 characters and use lowercase letters, numbers, or dashes.');
    }

    if (monitorIds.length === 0) {
      errors.push('Select at least one monitor.');
    }

    return {
      errors,
      payload: {
        name,
        slug,
        monitorIds
      }
    };
  }

  return {
    parseStatusPageForm,
    normalizeSlug
  };
}

module.exports = {
  createStatusPageValidation,
  normalizeSlug
};
