# Production release security checklist

A release is blocked until every mandatory item is evidenced.

- [ ] Security Gate green on the exact release commit.
- [ ] No known exploitable vulnerability accepted without documented risk decision.
- [ ] Machine-readable SBOM generated and archived.
- [ ] Production demo authentication disabled.
- [ ] Tenant isolation/IDOR regression suite green.
- [ ] AWS integration uses reviewed least-privilege STS AssumeRole and no stored long-lived keys.
- [ ] External AI data flow reviewed; secrets and unnecessary customer data excluded.
- [ ] Database migrations tested on a copy of representative data.
- [ ] Backup and restore exercise passed.
- [ ] Load/rate-limit failure modes tested.
- [ ] Installer and update artifacts signed; rollback tested.
- [ ] Threat model and cybersecurity risk assessment reviewed for this version.
- [ ] Secure installation/configuration instructions updated.
- [ ] Vulnerability disclosure/support contacts operational.
- [ ] Independent penetration test completed for first production release and material security architecture changes.
- [ ] CRA product classification/conformity route confirmed by competent legal/compliance review.
- [ ] GDPR roles, processor terms, retention and privacy information confirmed for actual deployment.
