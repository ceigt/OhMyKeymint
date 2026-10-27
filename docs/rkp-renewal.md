# Local RKP issuance and renewal

Local issuance uses the device RKP service to certify a newly generated software EC key.
The private key is kept on-device and is never included in a request or log.
Signed system proxy APKs may be owned by root or Android system (UID 1000), with no
non-owner write permissions. Auto falls back only during local CSR construction and
reports each attempted protocol. There is at most one certificate submission per call.

Automatic renewal is disabled by default. Tools > RKP automatic renewal offers explicit
V1 AIDL, V2, V1-native, or the last protocol successfully used by OMK. Importing an
existing Duck certificate does not identify its original interface; select V1 explicitly
when that is the device's known working protocol. Enabling requires consent to future
network requests, replacement, and OMK's existing retirement of keys bound to an old
attestation identity. Restoring a Keybox does not restore retired app keys.

The native root worker checks dates locally every six hours. The module daemon checks
the worker singleton once per minute and restarts a missing worker when consent or
recovery requires it. The WebUI reports both consent and live worker status. Only the final day triggers
issuance, with a persisted limit of two attempts in a rolling 24 hours. Clock rollback,
ambiguous submissions and unresolved replacement operations pause the worker.
A failed or interrupted pre-submission attempt retains its budget and retries only
after the persisted cooldown. Safe error codes, stages, timestamps and retry deadlines
are shown without CSR or response bodies. A failed public revocation-list download
keeps the pending candidate and retries after 15 minutes, one hour and three hours;
further failures pause for manual review. These read-only retries never spend the
signing submission budget. Acknowledging an
ambiguous submission retains a 24-hour cooldown. Disable Duck automatic renewal before
enabling OMK renewal. The worker does not alter TEE, provisioning, firmware or device IDs.

A candidate is checked for matching private key, dates, signatures, Google root pin,
CA constraints, longer validity and a fresh public Google revocation list. Certificate
serials are compared locally; they are not sent in a revocation query. Pending candidates
are reused. Active Keybox, PIF fingerprint, trust/patch configuration and relevant system
properties must remain stable throughout issuance and replacement. Renewal preserves
these settings; it does not sync or choose a new fingerprint or patch date.

Before replacement the worker durably records a root-private exact backup and transaction.
Cross-process compare-and-swap refuses to overwrite an unrelated replacement. A fresh
receipt from the same running KeyMint process must confirm loading the candidate, with
matching file hash and the configuration snapshot for this operation. A legitimate
PIF or patch update between operations becomes the next snapshot. Failure restores the recorded original when it is
still safe to do so; unresolved recovery pauses instead of overwriting another Keybox.
A restart recovers an unfinished transaction before allowing another submission.
Only unchanged, expired artifacts created by automatic renewal are cleaned up; current,
pending and manually issued artifacts are retained automatically. The staged-results
dialog offers explicit deletion, protects active and unfinished-operation results,
and warns near the 16-result capacity. Deletion never changes the installed Keybox. All renewal secrets/state are under
`/data/misc/keystore/omk/data/rkp-renewal/`, root-only, with bounded reads.

The shared data lock covers only the initial configuration snapshot, not network
requests or vendor CSR calls. Configuration is checked again before submission.

PIF fingerprint and synchronized trust patches can independently affect Play Integrity.
A valid certificate and a successful KeyMint load do not establish DEVICE or STRONG.
Test Play Store integrity separately after changes. No automatic Google app-data clearing,
process restart, system reboot or claim of STRONG success is part of renewal.

Validation: Android arm64 compilation, Clippy, formatting, WebUI type checking/build and
compiled workspace test binaries. Execute the Android test binaries and verify issuance,
reload/rollback, permissions and Play Integrity on a connected device before acceptance.
WebUI builds normalize Vue source newlines before scoped-style IDs are generated.
CI compares LF/CRLF fixture builds and verifies the committed WebUI assets after rebuilding.
