function createInvariantError(message, details = null) {
  const error = new Error(message);
  error.code = 'INVARIANT_VIOLATION';
  if (details) {
    error.details = details;
  }
  return error;
}

function assertInvariant(condition, message, details = null) {
  if (!condition) {
    throw createInvariantError(message, details);
  }
}

function assertOwnedByUser({ entityName, entityId = null, ownerUserId = null, userId = null }) {
  if (ownerUserId === null || ownerUserId === undefined) {
    return;
  }

  if (userId === null || userId === undefined) {
    return;
  }

  assertInvariant(
    String(ownerUserId) === String(userId),
    `${entityName} must belong to the current user.`,
    {
      entityId,
      ownerUserId,
      userId
    }
  );
}

function assertSelectedItemsBelongToUser({ entityName, requestedIds, matchedIds, userId }) {
  const requested = Array.from(new Set(Array.isArray(requestedIds) ? requestedIds : []));
  const matched = Array.isArray(matchedIds) ? matchedIds : [];
  assertInvariant(
    matched.length === requested.length,
    `Selected ${entityName} must belong to the current user.`,
    {
      userId,
      requestedIds: requested,
      matchedIds: matched
    }
  );
}

function assertRuntimePatchConsistency({ transition, patch }) {
  assertInvariant(
    patch && typeof patch === 'object',
    'Monitor runtime patch must be an object.',
    {
      transition
    }
  );

  assertInvariant(
    patch.status === transition,
    'Monitor runtime patch must preserve the requested transition status.',
    {
      transition,
      patchStatus: patch.status
    }
  );

  assertInvariant(
    patch.nextCheckAt === null,
    'Monitor runtime patch must clear nextCheckAt.',
    {
      transition,
      nextCheckAt: patch.nextCheckAt
    }
  );
}

module.exports = {
  assertInvariant,
  assertOwnedByUser,
  assertSelectedItemsBelongToUser,
  assertRuntimePatchConsistency
};
