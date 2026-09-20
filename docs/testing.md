# Testing strategy

## Current tests

- Risk unit tests validate bounds and explanations.
- Rule tests validate expected detections and stable fingerprints.
- API tests validate health, scan persistence, deduplication and filtering.
- API security tests cover missing/invalid tokens, role denials, cross-tenant reads,
  scan-ID probing, source isolation, transaction rollback, sanitized failure history,
  lock contention and explicit recovery.
- AWS SDK Stubber tests exercise IAM pagination and TCP ranges/all-protocol/IPv6
  collection; fake sessions verify ExternalId and expected account binding.
- Frontend tests cover login/sign-out, memory-only tokens, viewer restrictions,
  missing data, scan failures and stale-result messaging.
- CI performs lint, test, build, secret, SAST, dependency/filesystem and IaC
  scans.

## Required test for every new rule

Add one vulnerable asset that must match and one nearby safe asset that must not
match. This is necessary to control false positives, not merely code coverage.

CI runs backend tests against disposable SQLite and PostgreSQL databases. Locally,
SQLite is the default. Set CLOUDSHIELD_TEST_DATABASE_URL only to a disposable test
database: tests drop and recreate the application's tables. Never use a real database.

No AWS call is made by these tests. Stubber validates SDK request/response shapes;
it does not replace a separately authorized real sandbox acceptance test.

## Next tests

- Expand AWS response coverage to every service and permission-error outcome.
- CloudTrail event fixtures for every detection.
- Correlation time-window and out-of-order event tests.
- End-to-end fixture-to-dashboard test.
- PostgreSQL RLS, identity provider and tenant isolation property tests before external pilots.
