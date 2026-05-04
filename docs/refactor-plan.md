# Argus Refactor Plan

Branch context:
- Branch: `refactor/argus-core-split`
- Baseline commit: `a3e0c90` (`chore: start argus refactor plan`)

Goal:
- Reduce coupling between monitoring, persistence, alerting, and HTTP handling.
- Preserve behavior while making the codebase easier to reason about and extend.

## Execution Order

### Commit 1: Monitor lifecycle extraction

Scope:
- Move monitor state-transition rules out of `src/monitorEngine.js`.
- Introduce a domain module for confirmation retries, incident transitions, and recovery rules.
- Keep scheduling in the engine, but delegate semantic decisions.

Files:
- `src/monitorEngine.js`
- `src/domain/monitorLifecycle.js`
- `src/domain/monitorSnapshot.js`
- `test/monitor-engine.test.js`
- `test/domain/monitorLifecycle.test.js`

Definition of done:
- `monitorEngine` no longer contains the core down/up decision logic inline.
- Transition behavior is covered by pure unit tests.
- Existing engine tests still pass without lowering behavioral coverage.
- No alert or store behavior changes are introduced beyond the refactor boundary.

### Commit 2: Alert formatting and transport split

Scope:
- Separate alert message composition from webhook delivery.
- Keep Slack/Discord payload formatting in a pure presentation module.
- Keep HTTP delivery in a small transport module.

Files:
- `src/alerts.js`
- `src/alerts/presentation.js`
- `src/alerts/transport.js`
- `test/alerts.test.js`
- `test/alerts.transport.test.js`

Definition of done:
- Alert text and payload generation can be tested without HTTP calls.
- Delivery failures are still surfaced through the same return shape.
- Slack and Discord formatting remain behaviorally equivalent.
- Existing alert tests continue to pass.

### Commit 3: Web app decomposition

Scope:
- Reduce `src/app.js` to application bootstrap and route registration.
- Move feature handlers into route or controller modules.
- Keep auth/session middleware reusable.

Files:
- `src/app.js`
- `src/routes/auth.js`
- `src/routes/monitors.js`
- `src/routes/groups.js`
- `src/routes/statusPages.js`
- `src/controllers/*`

Definition of done:
- `app.js` is mostly wiring, not business logic.
- Route handlers are grouped by domain instead of by HTTP verb only.
- Authentication and authorization paths remain unchanged.
- Web and API behavior remain identical from the user perspective.

### Commit 4: Repository split

Scope:
- Break `DataStore` into focused repository modules.
- Keep schema/migration bootstrap centralized.
- Move query and mutation logic into domain-specific repositories.

Files:
- `src/store.js`
- `src/repositories/usersRepository.js`
- `src/repositories/monitorsRepository.js`
- `src/repositories/incidentsRepository.js`
- `src/repositories/eventsRepository.js`
- `src/repositories/statusPagesRepository.js`
- `src/repositories/apiKeysRepository.js`
- `test/store.test.js`
- `test/repositories/*`

Definition of done:
- No repository file knows about unrelated tables.
- Schema creation still works from a single bootstrap path.
- Ownership and filtering semantics remain intact.
- Existing persistence tests are either preserved or replaced with equivalent coverage.

### Commit 5: Check adapter formalization

Scope:
- Turn `src/checkers.js` into a dispatcher over focused check adapters.
- Isolate ping, HTTP, and keyword checks.
- Normalize result shapes in one place.

Files:
- `src/checkers.js`
- `src/checks/checkResult.js`
- `src/checks/ping.js`
- `src/checks/http.js`
- `src/checks/keyword.js`
- `test/checkers.test.js`

Definition of done:
- Each check type can be tested directly.
- Adding a new probe type does not require editing unrelated parsing code.
- Result shape remains stable for the engine and alerting layers.
- Existing checker tests still pass.

### Commit 6: Validation and observability cleanup

Scope:
- Move request validation to dedicated schema or validator modules.
- Add structured logging around critical monitor and alert events.
- Add invariant checks where runtime state can drift.

Files:
- `src/validation/monitors.js`
- `src/validation/groups.js`
- `src/validation/auth.js`
- `src/validation/statusPages.js`
- `src/observability/logger.js`
- `src/monitorEngine.js`
- `src/alerts.js`
- `src/app.js`

Definition of done:
- Request validation is consistent across web and API paths.
- Important state transitions are logged in a structured way.
- Invalid runtime states are caught early instead of leaking into the UI.
- No behavior regressions are introduced in auth or monitor edits.

### Commit 7: Behavior-level test expansion

Scope:
- Add integration coverage for the important monitor and page flows.
- Shift the strongest assertions to domain and repository boundaries.
- Keep the existing unit tests, but reduce reliance on internals.

Files:
- `test/integration/monitorLifecycle.test.js`
- `test/integration/apiMonitorFlow.test.js`
- `test/integration/statusPageFlow.test.js`
- `test/domain/*`
- `test/repositories/*`

Definition of done:
- Core monitor lifecycle behavior is covered end to end.
- Monitor CRUD, down detection, recovery, and status page flows are verified.
- The refactor can be changed again without rewriting every test.

## Working Rules For The Refactor

- Keep each commit small and reversible.
- Do not mix route extraction with storage refactors.
- Do not change user-visible behavior unless the commit explicitly requires it.
- Preserve production deployability after every commit.
- Run the full test suite before moving to the next commit.

## Recommended Stop Points

If the work needs to be paused, stop after:
- Commit 1 if you want the biggest architecture win with minimal surface area.
- Commit 3 if you want a cleaner HTTP layer before touching persistence.
- Commit 4 if you want the data layer to be maintainable before broader cleanup.

