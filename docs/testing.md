# Testing strategy

## Current tests

- Risk unit tests validate bounds and explanations.
- Rule tests validate expected detections and stable fingerprints.
- API tests validate health, scan persistence, deduplication and filtering.
- Frontend smoke test validates the safe empty state.
- CI performs lint, test, build, secret, SAST, dependency/filesystem and IaC
  scans.

## Required test for every new rule

Add one vulnerable asset that must match and one nearby safe asset that must not
match. This is necessary to control false positives, not merely code coverage.

## Planned V2 tests

- Recorded AWS API responses for collector error and pagination behavior.
- CloudTrail event fixtures for every detection.
- Correlation time-window and out-of-order event tests.
- End-to-end fixture-to-dashboard test.
- Tenant isolation property tests before any multi-tenant release.

