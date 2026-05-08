# Argus Post-Refactor Completion Plan

Branch context:
- Branch: `refactor/argus-core-split`
- Current head at plan time: `85ca7e3`

Purpose:
- Finish the remaining architecture cleanup without regressing behavior.
- Remove the last large coupling points between HTTP, query assembly, persistence, and runtime lifecycle logic.
- Keep each commit small, reviewable, and deployable.

## End State

Argus should end up with:
- A thin `app.js` that wires middleware, routes, and startup only.
- Query services for dashboard/public status snapshots instead of ad hoc view composition in the app layer.
- True repository modules for persistence instead of a compatibility facade around one giant store object.
- A monitor lifecycle that depends on a narrow persistence port and emits structured outcomes.
- A test suite that uses fast seam tests for most logic and a small number of subprocess integration tests for the critical full-stack paths.
- Explicit invariants around ownership, incidents, and monitor runtime state.

## Commit Plan

### Commit 8: Extract query services for dashboard and public status pages

Goal:
- Move the remaining snapshot composition logic out of `src/app.js`.
- Keep the existing EJS templates and route behavior unchanged.

Scope:
- Extract dashboard snapshot building into a dedicated query service.
- Extract public status page snapshot building into a dedicated query service.
- Keep the helper logic pure and testable without Express.
- Leave `app.js` as route composition plus response rendering.

Files:
- `src/app.js`
- `src/queries/dashboardSnapshot.js`
- `src/queries/publicStatusSnapshot.js`
- `test/queries/dashboardSnapshot.test.js`
- `test/queries/publicStatusSnapshot.test.js`

Definition of done:
- `app.js` no longer contains the bulk of snapshot assembly logic.
- Dashboard and public status snapshots are covered by pure unit tests.
- The rendered UI and API payloads remain behaviorally identical.
- The query services can be exercised without a running HTTP server.

Why this is next:
- It removes the last major business-logic block from the HTTP layer.
- It creates a cleaner boundary before the persistence split is made stricter.

### Commit 9: Convert the store facade into true repositories

Goal:
- Replace the current grouped facade with actual persistence modules that own their tables and query sets.

Scope:
- Move user and API-key logic into separate repository modules.
- Move group and status-page logic into separate repository modules.
- Move monitor, incident, and event logic into separate repository modules.
- Keep `src/store.js` limited to schema bootstrap, migrations, and connection ownership.
- Keep compatibility shims only as long as needed for migration.

Files:
- `src/store.js`
- `src/repositories/usersRepository.js`
- `src/repositories/apiKeysRepository.js`
- `src/repositories/groupsRepository.js`
- `src/repositories/statusPagesRepository.js`
- `src/repositories/monitorsRepository.js`
- `src/repositories/incidentsRepository.js`
- `src/repositories/eventsRepository.js`
- `src/repositories/index.js`
- `test/repositories/*`
- `test/store.test.js`

Definition of done:
- Repository modules stop sharing unrelated table knowledge.
- The store object is no longer the primary place where CRUD logic lives.
- Ownership and filtering semantics still match current behavior.
- The compatibility layer can be removed or reduced without breaking tests.

Why this is next:
- This is the largest remaining long-term maintenance risk.
- It makes the lifecycle refactor safer because the lifecycle can depend on narrower persistence ports.

### Commit 10: Narrow the monitor lifecycle persistence contract

Goal:
- Make monitor lifecycle logic depend on explicit repository ports instead of the broad store/facade object.

Scope:
- Introduce a lifecycle persistence adapter or repository interface.
- Limit lifecycle dependencies to the exact methods it needs.
- Keep alert delivery and state transitions separate.
- Preserve current retry, incident, and recovery semantics.

Files:
- `src/domain/monitorLifecycle.js`
- `src/monitorEngine.js`
- `src/domain/monitorSnapshot.js`
- `src/repositories/*` or a new `src/ports/*` layer
- `test/domain/monitorLifecycle.test.js`
- `test/monitor-engine.test.js`

Definition of done:
- The lifecycle no longer reaches through a broad store object for unrelated operations.
- Transition tests can use a fake repository port cleanly.
- Alerting and incident transitions remain behaviorally unchanged.
- The lifecycle contract is explicit enough that future storage changes do not require touching business logic.

Why this is next:
- It is the key architectural seam between runtime state and persistence.
- Once this is in place, the lifecycle can be maintained independently of the database shape.

### Commit 11: Add invariant checks and tighten structured logging

Goal:
- Catch impossible or inconsistent runtime state at the point it is created.

Scope:
- Add explicit invariant helpers for monitor runtime and incident state.
- Validate ownership consistency when monitors, groups, and status pages are mutated.
- Log invariant violations with enough context to debug them quickly.
- Keep the new checks narrow and predictable, not noisy.

Files:
- `src/observability/logger.js`
- `src/monitorEngine.js`
- `src/domain/monitorLifecycle.js`
- `src/store.js`
- `src/repositories/*`
- `test/domain/*`
- `test/repositories/*`

Definition of done:
- Invalid state is detected earlier than rendering or alerting time.
- Invariant failures are explicit and actionable.
- Structured logging still works with partial logger stubs in tests.
- The checks do not introduce new false positives in the normal flows.

Why this is next:
- After the persistence and lifecycle seams are clean, invariants become much more useful.
- This is where the system gets safer rather than merely more modular.

### Commit 12: Consolidate seam tests and prune redundant internals

Goal:
- Make the test suite reflect the new architecture instead of the old one.

Scope:
- Keep the existing unit tests that prove behavior.
- Add missing contract tests where seams are still under-covered.
- Remove or simplify tests that assert fragile implementation details.
- Keep subprocess integration tests only for the critical full-stack flows.

Files:
- `test/integration/*`
- `test/domain/*`
- `test/repositories/*`
- `test/queries/*`
- `test/alerts.test.js`
- `test/checkers.test.js`
- `test/validation.test.js`

Definition of done:
- Most behavior is covered at the seam level.
- The integration tests stay focused on end-to-end smoke coverage.
- The test suite is easier to maintain after future refactors.
- There is no excess duplication between unit, seam, and integration tests.

Why this is last:
- It is the natural cleanup after the architecture work is done.
- It lets us remove test noise only after the new boundaries have proven stable.

## Working Rules

- Keep every commit independently green.
- Prefer pure extraction before behavior changes.
- If a commit needs both an app change and a storage change, establish the storage boundary first.
- Do not broaden integration coverage when a seam test can prove the same behavior faster.
- If a new invariant is introduced, add a test for the invariant itself.

## Suggested Stop Points

- Stop after Commit 8 if you want the HTTP layer fully cleaned up first.
- Stop after Commit 9 if you want the data layer made structurally safe before touching lifecycle ports.
- Stop after Commit 11 if the system is architecturally sound and you only want test consolidation left.

## Completion

Status:
- The refactor plan has been carried through to completion on `refactor/argus-core-split`.
- The final cleanup pass reduced redundant store-level tests and removed a hardcoded integration helper path.
- The suite is green at the end state.

End-state summary:
- `app.js` is now a thin composition layer.
- Snapshot assembly lives in query services.
- Persistence logic lives in repositories rather than the old store monolith.
- The lifecycle depends on explicit repository ports.
- Ownership and runtime invariants are checked at mutation boundaries.
- The test suite now favors seam tests and keeps the store layer to a small compatibility smoke surface.
