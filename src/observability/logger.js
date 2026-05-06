function createStructuredLogger(baseLogger = console, context = {}) {
  function prefix(message) {
    if (!context || Object.keys(context).length === 0) {
      return message;
    }

    const scope = Object.entries(context)
      .map(([key, value]) => `${key}=${value}`)
      .join(' ');
    return `[${scope}] ${message}`;
  }

  function info(message, details = null) {
    if (typeof baseLogger.info === 'function') {
      if (details) {
        baseLogger.info(prefix(message), details);
      } else {
        baseLogger.info(prefix(message));
      }
      return;
    }

    if (details) {
      baseLogger.log(prefix(message), details);
      return;
    }

    baseLogger.log(prefix(message));
  }

  function warn(message, details = null) {
    if (typeof baseLogger.warn === 'function') {
      if (details) {
        baseLogger.warn(prefix(message), details);
      } else {
        baseLogger.warn(prefix(message));
      }
      return;
    }

    info(message, details);
  }

  function error(message, error = null, details = null) {
    const payload = details || null;

    if (typeof baseLogger.error === 'function') {
      if (error) {
        baseLogger.error(prefix(message), error, payload || undefined);
      } else if (payload) {
        baseLogger.error(prefix(message), payload);
      } else {
        baseLogger.error(prefix(message));
      }
      return;
    }

    if (error) {
      baseLogger.log(prefix(message), error, payload || undefined);
      return;
    }

    if (payload) {
      baseLogger.log(prefix(message), payload);
      return;
    }

    baseLogger.log(prefix(message));
  }

  return {
    info,
    warn,
    error
  };
}

function normalizeLogger(logger = console) {
  const fallback = logger || console;
  return {
    info: typeof fallback.info === 'function' ? fallback.info.bind(fallback) : () => {},
    warn:
      typeof fallback.warn === 'function'
        ? fallback.warn.bind(fallback)
        : typeof fallback.info === 'function'
          ? fallback.info.bind(fallback)
          : () => {},
    error:
      typeof fallback.error === 'function'
        ? fallback.error.bind(fallback)
        : typeof fallback.warn === 'function'
          ? fallback.warn.bind(fallback)
          : typeof fallback.info === 'function'
            ? fallback.info.bind(fallback)
            : () => {}
  };
}

module.exports = {
  createStructuredLogger,
  normalizeLogger
};
