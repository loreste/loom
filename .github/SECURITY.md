# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub Private Vulnerability
Reporting for this repository. Do not open a public issue or include real
credentials, approval tokens, customer data, SQL, or unrestricted request
bodies. Include the affected release/commit, deployment shape, a minimal
synthetic reproduction, impact, and any mitigation.

Maintainers acknowledge reports privately, reproduce them, assign severity,
coordinate a fix and patched release, and request a CVE when the issue is
eligible. Disclosure timing is coordinated with the reporter and affected
downstream users.

## Supported versions

The latest minor release and its latest patch release receive security fixes.
Older releases are unsupported unless a release note says otherwise. Pin
immutable release tags and verify checksums, signatures, SBOMs, and provenance
before installation.

## Dependency exceptions

Every accepted dependency or action exception must name an owner, mitigation,
tracking issue, and expiration date no longer than 90 days away. CI must fail
when an exception expires; renewal requires a new risk review and date.

## Security readiness

The repository publishes a threat model and operational security guidance.
Production v1.0 additionally requires an independent penetration test with no
unresolved critical or high findings, plus a recorded cryptographic key
lifecycle and incident-response review.
