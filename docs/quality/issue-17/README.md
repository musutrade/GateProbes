# Native publication integrity and immutable protection

Verified on 2026-10-14. Native RC8 is **published, prerelease, mutable**:
`draft=false`, `prerelease=true`, `immutable=false`. This is an acknowledged
legacy asset-protection limitation, not an integrity failure or a reason to
promote RC8 to stable. No release, tag, asset, signature or source is modified.

[The fresh public verification](rc8-public-verification.json) binds source
`155b233fb2f525f520b4fcc0ed73e017154345e0`, exact tag and certificate identity,
30 downloaded files and ten signed/attested subjects. Every public asset's
size and SHA-256 matches the API and signed inventory. Every subject passes
Cosign verification and GitHub attestation verification with exact certificate
SAN, source ref, source digest and signer digest. The API release ID and asset
set are checked again afterward. Commands and exit codes are in the receipt;
this is public-byte verification, not new platform runtime certification.

[Repository settings](immutability-settings.json) show immutable releases enabled.
[Tag ruleset 24964258](release-tag-rules.json) is active, includes the native
prefix, forbids tag update/deletion and has no bypass actor. Tag rules protect
tag identity, not release asset bytes. Consumers must keep pinned digests and
exact signature/source verification for this legacy release.

[GitHub documentation](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes)
states that enabling immutability only affects future releases. There is no
supported retroactive lock under the requirement to keep this published release
and its tag/bytes/signatures unchanged. RC8 will not be unpublished, recreated,
resigned or overwritten to acquire an immutable label.

## Future publication enforcement

`tools/release/verify_native_release.py preflight` requires the repository's
actual immutable setting before staging/signing/publication. After publication,
`verify` downloads the public assets into a fresh temporary directory and checks
the exact signed inventory, source/tag, every API digest/size, signatures and
provenance. Actual release `draft`, `prerelease` and `immutable` states are mandatory;
missing or false immutability fails. A prerelease tag requires `prerelease=true`;
a stable tag requires false. Existing releases are still refused by the workflow.

The protected native publication job keeps policy/build dependencies, environment
approval and keyless signing. A bounded 90-day artifact retains preflight and
publication receipts, including failure receipts; an unprotected publication
fails the job and never produces a successful protection receipt. It is not
silently recreated or rolled back after failure.

The manual `--historical-rc8` audit exception is restricted to the exact RC8 tag,
absent from the workflow, and records `protection_status=legacy-mutable`.
[The normal verifier rejection](rc8-strict-rejection.json) proves this release
does not satisfy future publication protection. Unknown immutable values fail
in both modes. The exception is not a waiver for future tags.

## Validation and rollback

The local governance suite passes 73 tests. Regressions reject missing/disabled
settings, draft or wrong RC/stable state, mutable future releases, wrong source
or identity inputs, duplicate/extra/missing assets, bad sizes/digests and changed
release identity during verification. They verify exact cryptographic source/tag
arguments and that the workflow cannot use the historical exception. YAML parsing,
documentation consistency and diff checks pass. Hosted PR acceptance is separate.

The original tagged RC8 workflow and release remain unchanged. Reverting these
future safeguards requires review and does not authorize weakening immutable
publication, moving tags or replacing assets. Measurement, baseline/debt/ratchet,
required gates and Rust Core decision authority remain unchanged.
